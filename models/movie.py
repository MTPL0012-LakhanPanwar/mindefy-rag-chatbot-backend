from pydantic import BaseModel
from typing import List, Optional

class MovieResponse(BaseModel):
    title: str
    movie_id: int
    poster_url: Optional[str] = None
    release_year: Optional[int] = None
    rating: Optional[float] = None
    genres: List[str] = []

class MovieDetailResponse(BaseModel):
    title: str
    movie_id: int
    poster_url: Optional[str] = None
    rating: Optional[float] = None
    release_date: Optional[str] = None
    runtime: Optional[int] = None
    language: Optional[str] = None
    genres: List[str] = []
    overview: Optional[str] = None

class RecommendationResponse(BaseModel):
    title: str
    movie_id: int
    relevance_score: float
    poster_url: Optional[str] = None
    release_year: Optional[int] = None
    rating: Optional[float] = None
    genres: List[str] = []

class RecommendationRequest(BaseModel):
    liked_movies: List[str]
    top_n: int = 12

class PersonalizedRecommendationsResponse(BaseModel):
    liked_movies: List[str]
    recommendations: List[RecommendationResponse]
    total_returned: int

class SearchResponse(BaseModel):
    results: List[MovieResponse]
    total: int

class MovieFullDetailResponse(BaseModel):
    title: str
    movie_id: int
    poster_url: Optional[str] = None
    overview: Optional[str] = None
    release_year: Optional[int] = None
    runtime: Optional[int] = None
    language: Optional[str] = None
    genres: List[str] = []
    rating: Optional[float] = None
    cast_and_crew: List[str] = []
    directors: List[str] = []

class SimilarMovieItem(BaseModel):
    title: str
    movie_id: int
    poster_url: Optional[str] = None
    rating: Optional[float] = None
    release_year: Optional[int] = None

class MovieDetailsWithSimilarResponse(BaseModel):
    movie: MovieFullDetailResponse
    similar_movies: List[SimilarMovieItem]