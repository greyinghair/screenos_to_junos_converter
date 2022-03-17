from .master_class import master
from .time import timestamp

def converted_config_output(line):  # Write Junos config to (OUTPUT)
    converted = open(f'converted_{timestamp}.txt', "a")
    converted.write(line + "\n")  # Write converted config and newline
    master.succeeded += 1
    converted.close()  # Close file


def junk_file_output(line):  # Write lines not conforming to logic to a junk file for later review
    junk = open(f'not_converted_{timestamp}.txt', "a")
    junk.write(line)  # Write line to file for later review
    master.failed += 1
    junk.close()  # Close file