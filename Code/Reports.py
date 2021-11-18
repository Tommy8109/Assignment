import csv

class MakeReport():
    def __init__(self):
        self.partiton_file = "Partition Report.csv"
        self.fs_file = "FS Report.csv"

    def partition_report(self, num, type, start, sectors):
        with open(self.partiton_file, 'a', newline='') as csvfile:
            linewriter = csv.writer(csvfile, delimiter='|',quotechar=chr(34), quoting=csv.QUOTE_MINIMAL)
            header = ["Number", "type", "Start", "Sectors"]
            newline = ""
            info = [num, type, start, sectors]
            linewriter.writerow(header)
            linewriter.writerow(info)
            linewriter.writerow(newline)

    def file_sys_report(self, fs, clusters, size, endian, meta, flags):
        with open(self.fs_file, 'a', newline='') as csvfile:
            linewriter = csv.writer(csvfile, delimiter='|',quotechar=chr(34), quoting=csv.QUOTE_MINIMAL)
            header = ["File sys", "Clusters", "Cluster size", "Endian", "Metadata", "Flags"]
            newline = ""
            info = [fs, clusters, size, endian, meta], flags
            linewriter.writerow(header)
            linewriter.writerow(info)
            linewriter.writerow(newline)

