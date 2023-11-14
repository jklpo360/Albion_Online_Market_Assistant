import psutil
import time

UPDATE_DELAY = 1 # in seconds https://thepythoncode.com/article/make-a-network-usage-monitor-in-python

def get_size(bytes):
    """
    Returns size of bytes in a nice format
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024