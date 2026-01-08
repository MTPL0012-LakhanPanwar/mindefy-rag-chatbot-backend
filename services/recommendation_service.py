import numpy as np
from typing import List, Dict
from sklearn.metrics.pairwise import cosine_similarity
from concurrent.futures import ThreadPoolExecutor

from core.data_loader import DataLoader
from services.tmdb_service import TMDBService

class RecommendationService:
    def __init__(self):
        self.data_loader = DataLoader()
        self.movies = self.data_loader.get_movies()
        self.similarity = self.data_loader.get_similarity_matrix()
        self.movie_vectors = self.data_loader.get_movie_vectors()
        self.tmdb_service = TMDBService()
    
    def get_similar_movies(self, movie_title: str, top_n: int = 5) -> List[Dict]:
        """
        Get similar movies based on content similarity
        """
        # Find movie index
        movie_matches = self.movies[self.movies["title"].str.lower() == movie_title.lower()]
        
        if movie_matches.empty:
            raise ValueError(f"Movie '{movie_title}' not found in database")
        
        idx = movie_matches.index[0]
        scores = self.similarity[idx]
        
        # Get top N similar movies (excluding the movie itself)
        ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)[1:top_n+1]
        
        recommendations = []
        movie_ids = []
        
        for i, score in ranked:
            movie = self.movies.iloc[i]
            movie_ids.append(int(movie.movie_id))
            recommendations.append({
                "title": movie.title,
                "movie_id": int(movie.movie_id),
                "similarity_score": float(score)
            })
        
        # Fetch posters in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            posters = list(executor.map(self.tmdb_service.get_poster_url, movie_ids))
        
        for i, poster_url in enumerate(posters):
            recommendations[i]["poster_url"] = poster_url
        
        return recommendations
    
    def get_personalized_recommendations(self, liked_movies: List[str], top_n: int = 5) -> List[Dict]:
        """
        Get personalized recommendations based on user's liked movies
        Uses average of movie vectors for user profile
        """
        if not liked_movies:
            return []
        
        # Find indices of liked movies
        liked_idx = []
        for movie_title in liked_movies:
            matches = self.movies[self.movies["title"].str.lower() == movie_title.lower()]
            if not matches.empty:
                liked_idx.append(matches.index[0])
        
        if not liked_idx:
            raise ValueError("None of the liked movies found in database")
        
        # Create user profile vector (average of liked movie vectors)
        user_vector = np.mean(self.movie_vectors[liked_idx], axis=0)
        
        # Calculate similarity with all movies
        scores = cosine_similarity(user_vector.reshape(1, -1), self.movie_vectors)[0]
        ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
        
        # Filter out already liked movies and get top N
        # Create a set of normalized liked movie titles for case-insensitive comparison
        liked_movies_normalized = {movie_title.lower() for movie_title in liked_movies}
        
        recommendations = []
        movie_ids = []
        
        for i, score in ranked:
            movie = self.movies.iloc[i]
            title = movie.title
            
            # Skip if already liked (case-insensitive comparison)
            if title.lower() in liked_movies_normalized:
                continue
            
            movie_ids.append(int(movie.movie_id))
            recommendations.append({
                "title": title,
                "movie_id": int(movie.movie_id),
                "relevance_score": float(score)
            })
            
            if len(recommendations) == top_n:
                break
        
        # Fetch posters in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:  # ← Changed from 5 to 10, fetch full details not just posters
            movie_details = list(executor.map(self.tmdb_service.get_movie_details, movie_ids))  # ← Changed from get_poster_url
            
            # Merge details into recommendations
        for i, details in enumerate(movie_details):
            if details:
                recommendations[i]["poster_url"] = details.get("poster_url")
                recommendations[i]["release_year"] = details.get("release_year")  
                recommendations[i]["rating"] = details.get("rating")              
                recommendations[i]["genres"] = details.get("genres", []) 
            else:         # ← NEW
                recommendations[i]["poster_url"] = None
                recommendations[i]["release_year"] = None  
                recommendations[i]["rating"] = None        
                recommendations[i]["genres"] = []          
        
        return recommendations
    