from fastapi import APIRouter, HTTPException, Query
from typing import List
from pydantic import BaseModel
from services.movie_service import MovieService
from services.recommendation_service import RecommendationService
from services.tmdb_service import TMDBService

router = APIRouter()

# Initialize services
movie_service = MovieService()
recommendation_service = RecommendationService()
tmdb_service = TMDBService()

# Import models from models folder
from models.movie import (
    MovieResponse,
    SearchResponse,
    RecommendationRequest,
    PersonalizedRecommendationsResponse,
    MovieDetailsWithSimilarResponse,
    SimilarMovieItem
)

@router.get("/")
async def movie_api_info():
    return {
        "message": "Movie Recommendation API",
        "version": "1.0.0",
    }

@router.get("/search", response_model=SearchResponse)
async def search_movies(
    q: str = Query(..., min_length=1, description="Search query (title, genre, cast, or keywords)"),
    skip: int = Query(0, ge=0, description="Number of results to skip (for pagination)"),
    limit: int = Query(10, ge=1, le=100, description="Number of results per page")
):
    """
    Search for movies by title, genre, cast, or keywords
    Returns paginated results with total count
    Priority: Title matches first, then genre/cast/keywords
    """
    try:
        data = movie_service.search_movies_paginated(query=q, skip=skip, limit=limit)
        return SearchResponse(results=data["results"], total=data["total"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/all")
async def get_all_movies(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000)
):
    """
    Get all movies in the database (paginated)
    """
    try:
        movies = movie_service.get_all_movies(skip, limit)
        total = movie_service.get_total_count()
        return {
            "movies": movies,
            "total": total,
            "skip": skip,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/details-with-similar/{title}", response_model=MovieDetailsWithSimilarResponse)
async def get_movie_details_with_similar(
    title: str,
    limit: int = Query(5, ge=1, le=20, description="Number of similar movies")
):
    """
    Get full movie details by title along with a list of similar movies.
    """
    try:
        movie = movie_service.get_movie_by_title(title)
        if not movie:
            raise HTTPException(status_code=404, detail="Movie not found")

        details = tmdb_service.get_movie_full_details(movie["movie_id"])
        if not details:
            raise HTTPException(status_code=404, detail="Movie not found")

        try:
            recommendations = recommendation_service.get_similar_movies(title, limit)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        similar_movies: List[dict] = []
        for rec in recommendations:
            mid = rec.get("movie_id")
            if mid is None:
                continue
            brief = tmdb_service.get_movie_brief(int(mid))
            item = {
                "title": rec.get("title"),
                "movie_id": int(mid),
                "poster_url": (brief or {}).get("poster_url") or rec.get("poster_url"),
                "rating": (brief or {}).get("rating"),
                "release_year": (brief or {}).get("release_year"),
            }
            similar_movies.append(item)

        return {
            "movie": details,
            "similar_movies": similar_movies,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/recommendations/personalized", response_model=PersonalizedRecommendationsResponse)
async def get_personalized_recommendations(request: RecommendationRequest):
    """
    Get personalized recommendations based on liked movies
    Returns movie details including release year, rating, and genres
    """
    try:
        if not request.liked_movies:
            raise HTTPException(status_code=400, detail="No liked movies provided")

        if request.top_n < 1 or request.top_n > 100:
            raise HTTPException(status_code=400, detail="top_n must be between 1 and 100")
        
        recommendations = recommendation_service.get_personalized_recommendations(
            request.liked_movies, 
            request.top_n
        )
        return PersonalizedRecommendationsResponse(
            liked_movies=request.liked_movies,
            recommendations=recommendations,
            total_returned=len(recommendations)
        )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def movie_health_check():
    """
    Health check endpoint for movie service
    """
    return {"status": "healthy", "service": "movies"}