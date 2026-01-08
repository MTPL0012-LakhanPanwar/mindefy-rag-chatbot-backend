import pandas as pd
import numpy as np
from typing import List, Dict, Optional
from core.config import settings
from core.data_loader import DataLoader
from services.tmdb_service import TMDBService

class MovieService:
    def __init__(self):
        self.data_loader = DataLoader()
        self.movies = self.data_loader.get_movies()
        self.tmdb_service = TMDBService()

        if "_title_norm" not in self.movies.columns:
            self.movies["_title_norm"] = (
                self.movies["title"].astype(str).str.lower().str.replace(" ", "", regex=False).str.replace("-", "", regex=False)
            )

        if "tags" in self.movies.columns and "_tags_norm" not in self.movies.columns:
            self.movies["_tags_norm"] = self.movies["tags"].fillna("").astype(str).str.lower()
    
    def search_movies_paginated(self, query: str, skip: int = 0, limit: int = 10) -> Dict:
        query = (query or "").strip().lower()
        if not query:
            return {"results": [], "total": 0}

        norm_query = query.replace(" ", "").replace("-", "")

        title_norm = self.movies["_title_norm"]
        title_contains = title_norm.str.contains(norm_query, na=False)
        title_starts = title_norm.str.startswith(norm_query, na=False)

        if "_tags_norm" in self.movies.columns:
            tags_contains = self.movies["_tags_norm"].str.contains(query, na=False)
        else:
            tags_contains = pd.Series(False, index=self.movies.index)

        any_match = title_contains | tags_contains

        matched = self.movies.loc[any_match, ["title", "movie_id"]].copy()
        if matched.empty:
            return {"results": [], "total": 0}

        score = np.zeros(len(self.movies), dtype=np.int16)
        score[title_contains.to_numpy()] += 100
        score[title_starts.to_numpy()] += 50
        score[tags_contains.to_numpy()] += 10

        matched["_score"] = score[any_match.to_numpy()]
        matched.sort_values(["_score", "title"], ascending=[False, True], inplace=True)

        total = int(len(matched))
        page = matched.iloc[skip:skip + limit]

        results: List[Dict] = []
        for _, row in page.iterrows():
            movie_id = int(row["movie_id"])
            results.append({
                "title": row["title"],
                "movie_id": movie_id,
                "poster_url": self._get_poster_url(movie_id)
            })

        return {"results": results, "total": total}

    def search_movies(self, query: str, limit: int = 10) -> List[Dict]:
        data = self.search_movies_paginated(query=query, skip=0, limit=limit)
        return data["results"]
    
    def get_movie_by_title(self, title: str) -> Optional[Dict]:
        """
        Get a movie by exact title match (case-insensitive)
        """
        row = self.movies[self.movies["title"].str.lower() == title.lower()]
        
        if row.empty:
            return None
        
        movie = row.iloc[0]
        return {
            "title": movie["title"],
            "movie_id": int(movie["movie_id"]),
            "poster_url": self._get_poster_url(int(movie["movie_id"]))
        }
    
    def get_movie_by_id(self, movie_id: int) -> Optional[Dict]:
        """
        Get a movie by movie_id
        """
        row = self.movies[self.movies["movie_id"] == movie_id]
        
        if row.empty:
            return None
        
        movie = row.iloc[0]
        return {
            "title": movie["title"],
            "movie_id": int(movie["movie_id"]),
            "poster_url": self._get_poster_url(int(movie["movie_id"]))
        }
    
    def get_all_movies(self, skip: int = 0, limit: int = 100) -> List[Dict]:
        """
        Get all movies with pagination
        """
        movies_slice = self.movies.iloc[skip:skip + limit]
        
        results = []
        for _, row in movies_slice.iterrows():
            movie_id = int(row["movie_id"])
            results.append({
                "title": row["title"],
                "movie_id": movie_id,
                "poster_url": self._get_poster_url(movie_id),
                "release_year": self.tmdb_service.get_release_year(movie_id)
            })
        
        return results
    
    def get_total_count(self) -> int:
        """
        Get total number of movies in database
        """
        return len(self.movies)
    
    def _get_poster_url(self, movie_id: int) -> str:
        """
        Fetch poster URL from TMDB service
        """
        return self.tmdb_service.get_poster_url(movie_id)