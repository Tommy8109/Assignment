import csv

class MakeReport():
    def __init__(self):
        self.partiton_file = "Partition Report.csv"
        self.fs_file = "FS Report.csv"
        self.files = "Found file report.csv"

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
            info = [fs, clusters, size, endian, meta, flags]
            linewriter.writerow(header)
            linewriter.writerow(info)
            linewriter.writerow(newline)

    def files_report(self, name, type, record_num, acc_time, crtime, modtime, metatime, gid, size, status):
        with open(self.files, 'a', newline='') as csvfile:
            linewriter = csv.writer(csvfile, delimiter='|',quotechar=chr(34), quoting=csv.QUOTE_MINIMAL)
            header = ["Name", "Type", "Metadata record", "Created", "Accessed", "Modified", "Metadata change",
                      "Group ID", "size", "status"]
            newline = ""
            info = [name, type, record_num, crtime, acc_time, modtime, metatime, size, status]
            linewriter.writerow(header)
            linewriter.writerow(info)
            linewriter.writerow(newline)
