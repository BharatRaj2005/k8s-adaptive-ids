import warnings

# scikit-learn emits this once per tree when forest models predict in joblib
# threads under Python 3.14; it does not affect results.
warnings.filterwarnings("ignore", message=r"`sklearn\.utils\.parallel\.delayed` should be used", category=UserWarning)
