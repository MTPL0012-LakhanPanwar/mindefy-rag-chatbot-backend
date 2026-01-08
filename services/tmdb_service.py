import requests
from typing import List, Dict, Optional
from functools import lru_cache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.config import settings


class TMDBService:
    def __init__(self):
        self.base_url = "https://api.themoviedb.org/3"
        self.api_key = settings.TMDB_API_KEY
        self.poster_base = settings.POSTER_BASE_URL

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json"
        })

        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)

    # ------------------------------------------------------------------
    # INTERNAL SHARED FETCH (NEW – DOES NOT BREAK ANY CALLERS)
    # ------------------------------------------------------------------

    @lru_cache(maxsize=3000)
    def _fetch_movie(self, movie_id: int, with_credits: bool = False) -> Optional[Dict]:
        params = {"api_key": self.api_key}
        if with_credits:
            params["append_to_response"] = "credits"

        url = f"{self.base_url}/movie/{movie_id}"

        try:
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                return None
            print(f"TMDB HTTP error ({movie_id}): {e}")
            return None
        except requests.RequestException as e:
            print(f"TMDB network error ({movie_id}): {e}")
            return None

    # ------------------------------------------------------------------
    # EXISTING PUBLIC METHODS (UNCHANGED SIGNATURES)
    # ------------------------------------------------------------------

    def get_poster_url(self, movie_id: int) -> Optional[str]:
        data = self._fetch_movie(movie_id)
        if not data:
            return None

        poster_path = data.get("poster_path")
        return f"{self.poster_base}{poster_path}" if poster_path else None

    @lru_cache(maxsize=1000)
    def get_release_year(self, movie_id: int) -> Optional[int]:
        data = self._fetch_movie(movie_id)
        if not data:
            return None

        release_date = data.get("release_date")
        return int(release_date[:4]) if release_date and len(release_date) >= 4 else None

    def get_movie_details(self, movie_id: int) -> Optional[Dict]:
        data = self._fetch_movie(movie_id)
        if not data:
            return None

        release_date = data.get("release_date", "")
        release_year = int(release_date[:4]) if release_date and len(release_date) >= 4 else None

        return {
            "title": data.get("title", "N/A"),
            "movie_id": movie_id,
            "poster_url": (
                f"{self.poster_base}{data['poster_path']}"
                if data.get("poster_path")
                else None
            ),
            "rating": data.get("vote_average"),
            "release_date": data.get("release_date"),
            "release_year": release_year,
            "runtime": data.get("runtime"),
            "language": (data.get("original_language") or "").upper(),
            "genres": [g["name"] for g in data.get("genres", [])],
            "overview": data.get("overview"),
        }

    @lru_cache(maxsize=1000)
    def get_movie_brief(self, movie_id: int) -> Optional[Dict]:
        data = self._fetch_movie(movie_id)
        if not data:
            return None

        release_date = data.get("release_date")
        release_year = int(release_date[:4]) if release_date and len(release_date) >= 4 else None

        return {
            "title": data.get("title"),
            "movie_id": int(data.get("id", movie_id)),
            "poster_url": (
                f"{self.poster_base}{data['poster_path']}"
                if data.get("poster_path")
                else None
            ),
            "rating": data.get("vote_average"),
            "release_year": release_year,
        }

    def get_movie_full_details(self, movie_id: int) -> Optional[Dict]:
        data = self._fetch_movie(movie_id, with_credits=True)
        if not data:
            return None

        release_date = data.get("release_date")
        release_year = int(release_date[:4]) if release_date and len(release_date) >= 4 else None

        credits = data.get("credits") or {}
        cast = credits.get("cast") or []
        crew = credits.get("crew") or []

        top_actors = sorted(
            cast,
            key=lambda c: c.get("order", 10**9)
        )[:10]

        directors = [
            d.get("name")
            for d in crew
            if d.get("job") == "Director" and d.get("name")
        ]

        return {
            "title": data.get("title", "N/A"),
            "movie_id": int(data.get("id", movie_id)),
            "poster_url": (
                f"{self.poster_base}{data['poster_path']}"
                if data.get("poster_path")
                else None
            ),
            "overview": data.get("overview"),
            "release_year": release_year,
            "runtime": data.get("runtime"),
            "language": (data.get("original_language") or "").upper(),
            "genres": [g["name"] for g in data.get("genres", [])],
            "rating": data.get("vote_average"),
            "cast_and_crew": [c.get("name") for c in top_actors if c.get("name")],
            "directors": directors,
        }

    def search_tmdb(self, query: str, limit: int = 10) -> List[Dict]:
        url = f"{self.base_url}/search/movie"
        params = {"api_key": self.api_key, "query": query}

        try:
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            results = response.json().get("results", [])[:limit]
        except requests.RequestException as e:
            print(f"Error searching TMDB: {e}")
            return []

        movies = []
        for movie in results:
            movies.append({
                "title": movie.get("title"),
                "movie_id": movie.get("id"),
                "poster_url": (
                    f"{self.poster_base}{movie['poster_path']}"
                    if movie.get("poster_path")
                    else None
                ),
                "rating": movie.get("vote_average"),
                "release_date": movie.get("release_date"),
            })

        return movies
