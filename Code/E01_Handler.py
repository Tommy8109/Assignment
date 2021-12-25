import pytsk3
import pyewf


class E01Handler(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        self.InfoList = []
        super(E01Handler, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
        # This super call is doing the same as (diskimage = pytsk3.Img_Info("Washer 17.E01"))

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()

    def case_info(self, forensic_image):
        header_values = forensic_image.get_header_values()
        self.InfoList.append(header_values['case_number'])
        self.InfoList.append(header_values['evidence_number'])
        self.InfoList.append(header_values['examiner_name'])
        self.InfoList.append(forensic_image.get_hash_values())

        return self.InfoList
