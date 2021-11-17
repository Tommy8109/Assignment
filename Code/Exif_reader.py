import exifread


class ExifTags():
    def __init__(self):
        """Set up lists that include the useful EXIF tags for GPS tag data and Image tag data """
        self.image_tags = ["Image Make", "Image Model", "Image Software", "Image DateTime"]
        self.gps_tags = ["GPS GPSLatitudeRef", "GPS GPSLongitudeRef", "GPS GPSLatitude", "GPS GPSLongitude"]

    def read_image_tags(self, filename):
        """
        Accepts filename as argument which is then opened as read binary
        and uses a for loop to loop through the tags, if the tag name matches
        one of the predefined "useful" ones, it is printed, else it is passed.
        """
        f = open(filename, "rb")
        tags = exifread.process_file(f)
        for tag in tags.keys():
            if tag in self.image_tags:
                print("%s: %s" % (tag, tags[tag]))
            else:
                pass

    def read_gps_tags(self, filename):
        """
        Accepts filename as argument which is then opened as read binary
        and uses a for loop to loop through the tags, if the tag name matches
        one of the predefined "useful" ones, it is printed, else it is passed.
        """
        f = open(filename, "rb")
        tags = exifread.process_file(f)
        for tag in tags.keys():
            if tag in self.gps_tags:
                print("%s: %s" % (tag, tags[tag]))
            else:
                pass

    def read_all(self, filename):
        """
        Accepts filename as argument which is then opened as read binary
        and uses a for loop to loop through the tags, this method will
        print out all tags, rather than a predefined set.
        """
        f = open(filename, "rb")
        tags = exifread.process_file(f)
        for tag in tags.keys():
            if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                print("%s: %s" % (tag, tags[tag]))
            else:
                pass
