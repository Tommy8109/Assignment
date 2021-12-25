import re

class GetExt():
    def __init__(self, filename):
        self.filename = filename
        self.pattern = r"(\..*)"

    def get(self):
        regex = re.compile(self.pattern)
        m = regex.search(self.filename)
        if m is not None:
            return m.group(1)
        else:
            return None

