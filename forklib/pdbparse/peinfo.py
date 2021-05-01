import binascii
import ntpath
import sys

from pefile import PE, DEBUG_TYPE, DIRECTORY_ENTRY

from pdbparse.dbgold import CV_RSDS_HEADER, CV_NB10_HEADER


class PENoDebugDirectoryEntriesError(Exception):
    pass


def get_pe_debug_data(filename):
    pe = PE(filename, fast_load = True)
    # we prefer CodeView data to misc
    type = u'IMAGE_DEBUG_TYPE_CODEVIEW'
    dbgdata = get_debug_data(pe, DEBUG_TYPE[type])
    if dbgdata is None:
        type = u'IMAGE_DEBUG_TYPE_MISC'
        dbgdata = get_debug_data(pe, DEBUG_TYPE[type])
        if dbgdata is None:
            type = None
    return dbgdata, type


def get_external_codeview(filename):
    """
        Extract filename's debug CodeView information.
        Parameter:
            * (bytes) filename, path to input PE 
        Return :
            * (str) the GUID
            * (str) the pdb filename
    """
    pe = PE(filename, fast_load = True)
    dbgdata = get_debug_data(pe, DEBUG_TYPE[u'IMAGE_DEBUG_TYPE_CODEVIEW'])
    if dbgdata[:4] == b'RSDS':
        (guid, filename) = get_rsds(dbgdata)
    elif dbgdata[:4] == b'NB10':
        (guid, filename) = get_nb10(dbgdata)
    else:
        raise TypeError(u'Invalid CodeView signature: [%s]' % dbgdata[:4])
    guid = guid.upper()
    return guid, filename


def get_debug_data(pe, type = DEBUG_TYPE[u'IMAGE_DEBUG_TYPE_CODEVIEW']):
    retval = None
    if not hasattr(pe, u'DIRECTORY_ENTRY_DEBUG'):
        # fast loaded - load directory
        pe.parse_data_directories(DIRECTORY_ENTRY[u'IMAGE_DIRECTORY_ENTRY_DEBUG'])
    if not hasattr(pe, u'DIRECTORY_ENTRY_DEBUG'):
        raise PENoDebugDirectoryEntriesError()
    else:
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            off = entry.struct.PointerToRawData
            size = entry.struct.SizeOfData
            if entry.struct.Type == type:
                retval = pe.__data__[off:off + size]
                break
    return retval


def get_dbg_fname(dbgdata):
    """
        Parse the MSIC header using construct.
        Parameter:
            * (bytes) dbgdata, the raw bytes header 
        Return :
            * (str) the .dbg filename
    """
    from pdbparse.dbgold import IMAGE_DEBUG_MISC
    dbgstruct = IMAGE_DEBUG_MISC.parse(dbgdata)
    raw_filename = dbgstruct.Strings[0].decode('ascii')
    return ntpath.basename(raw_filename)


def get_rsds(dbgdata):
    """
        Parse the RSDS header using construct.
        Parameter:
            * (bytes) dbgdata, the raw bytes header 
        Return :
            * (str) the GUID
            * (str) the pdb filename
    """
    dbg = CV_RSDS_HEADER.parse(dbgdata)
    guidstr = u"%08x%04x%04x%s%x" % (dbg.GUID.Data1, dbg.GUID.Data2, dbg.GUID.Data3, binascii.hexlify(
        dbg.GUID.Data4).decode('ascii'), dbg.Age)
    filename = ntpath.basename(dbg.Filename)
    return guidstr, filename


def get_nb10(dbgdata):
    """
        Parse the NB10 header using construct.
        Parameter:
            * (bytes) dbgdata, the raw bytes header 
        Return :
            * the GUID string (i.e. file timestamp)
            * the pdb filename str
    """
    dbg = CV_NB10_HEADER.parse(dbgdata)
    guidstr = u"%x%x" % (dbg.Timestamp, dbg.Age)
    filename = ntpath.basename(dbg.Filename)
    return guidstr, filename


def get_pe_guid(filename):
    """
        Return the PE GUID based on TimeDateStamp and SizeOfImage.
        Parameter:
            * (str) PE filename
        Returns:
            * (str) PE GUID
    """
    try:
        pe = PE(filename, fast_load = True)
    except IOError as e:
        print(e)
        sys.exit(-1)
    guidstr = "%x%x" % (pe.FILE_HEADER.TimeDateStamp, pe.OPTIONAL_HEADER.SizeOfImage)
    return guidstr
