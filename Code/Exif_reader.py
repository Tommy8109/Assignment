import exifread


class ExifTags():
    def __init__(self):
        """Set up lists that include the useful EXIF tags for GPS tag data and Image tag data """
        self.__image_tags = ["Image Make", "Image Model", "Image Software"]
        self.__gps_tags = ["GPS GPSLatitudeRef", "GPS GPSLongitudeRef", "GPS GPSLatitude", "GPS GPSLongitude"]
        self.gps_info = []
        self.image_info = []

    def read_image_tags(self, filename):
        """
        Accepts filename as argument which is then opened as read binary
        and uses a for loop to loop through the tags, if the tag name matches
        one of the predefined "useful" ones, it is printed, else it is passed.
        """
        f = open(filename, "rb")
        tags = exifread.process_file(f)
        for tag in tags.keys():
            if tag in self.__image_tags:
                self.image_info.append("%s" % (tags[tag]))

        return self.image_info

    def read_gps_tags(self, filename):
        """
        Accepts filename as argument which is then opened as read binary
        and uses a for loop to loop through the tags, if the tag name matches
        one of the predefined "useful" ones, it is printed, else it is passed.
        """
        f = open(filename, "rb")
        tags = exifread.process_file(f)
        for tag in tags.keys():
            if tag in self.__gps_tags:
                self.gps_info.append("%s" % (tags[tag]))
                print("%s" % (tags[tag]))

        return self.gps_info
