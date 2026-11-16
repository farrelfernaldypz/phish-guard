"""Training entry point delegates to inference feature extraction."""
from backend.app.services.feature_extraction import FEATURE_NAMES, extract_features, extract_feature_vector
__all__ = ["FEATURE_NAMES", "extract_features", "extract_feature_vector"]

