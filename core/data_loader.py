import pickle
import pandas as pd
import numpy as np
from pathlib import Path

class DataLoader:
    """
    Singleton class to load and cache movie data
    """
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DataLoader, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not DataLoader._initialized:
            self._load_data()
            DataLoader._initialized = True
    
    def _load_data(self):
        """
        Load all pickle files into memory
        """
        data_dir = Path("Datasets")
        
        try:
            # Load movie dictionary
            with open(data_dir / "movie_dict.pkl", "rb") as f:
                movies_dict = pickle.load(f)
            self.movies = pd.DataFrame(movies_dict)
            
            # Load similarity matrix
            with open(data_dir / "similarity.pkl", "rb") as f:
                self.similarity = pickle.load(f)
            
            # Load movie vectors
            with open(data_dir / "movie_vectors.pkl", "rb") as f:
                self.movie_vectors = pickle.load(f)
            
            # Load vectorizer
            with open(data_dir / "vectorizer.pkl", "rb") as f:
                self.vectorizer = pickle.load(f)
            
            print(f"✓ Loaded {len(self.movies)} movies")
            print(f"✓ Similarity matrix shape: {self.similarity.shape}")
            print(f"✓ Movie vectors shape: {self.movie_vectors.shape}")
            
        except FileNotFoundError as e:
            print(f"Error: Could not find data files in {data_dir}")
            raise e
        except Exception as e:
            print(f"Error loading data: {e}")
            raise e
    
    def get_movies(self) -> pd.DataFrame:
        """Return movies DataFrame"""
        return self.movies
    
    def get_similarity_matrix(self) -> np.ndarray:
        """Return similarity matrix"""
        return self.similarity
    
    def get_movie_vectors(self) -> np.ndarray:
        """Return movie vectors"""
        return self.movie_vectors
    
    def get_vectorizer(self):
        """Return TF-IDF vectorizer"""
        return self.vectorizer