import logging

class CuteHandler(logging.StreamHandler):
    def emit(self, record):
        color = hash(record.name) % 7 + 31
        try:
            record.name = ("\x1b[%dm" % color) + record.name + "\x1b[0m"
        except Exception:
            pass

        try:
            record.msg = ("\x1b[%dm" % color) + record.msg + "\x1b[0m"
        except Exception:
            pass

        super(CuteHandler, self).emit(record)

def getlogger(name):    
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    stream_handler = CuteHandler()
    stream_handler.setFormatter(logging.Formatter('%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'))
    logger.addHandler(stream_handler)

    return logger
