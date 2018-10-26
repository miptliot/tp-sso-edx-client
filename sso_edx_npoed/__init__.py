import os


try:
    import signals
except:
    msg = "Oh, it's not edx"
    pass

def get_base_path():
    return os.path.dirname(__file__)
