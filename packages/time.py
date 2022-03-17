from datetime import datetime
import time

start_time = time.time() # Used for overtime time of run
timenow = datetime.now() # Get date and time into variable
timestamp = timenow.strftime(f'%Y%m%d_%H%M%S') # Change to useable variable to append to filenames