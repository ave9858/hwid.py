import os
import xml.etree.ElementTree as ET
from base64 import b64decode, b64encode
from hashlib import sha256
from winreg import HKEY_LOCAL_MACHINE, OpenKey, QueryValueEx

GENERIC_PRODUCT_KEY = "W269N-WFGWX-YVC9B-4J6C9-T83GX"  # https://docs.microsoft.com/en-us/windows-server/get-started/kms-client-activation-keys

BLOB_HEADER = 0x0602000000A40000525341310008000001000100.to_bytes(20, "big")

# (private_key, public_key) Can be found by reverse engineering the whiteboxes in gatherosstate.exe and ClipUp.exe.
# CLIPUP_KEY = (
#     0x0,
#     0x0,
# )
# GATHEROSSTATE_KEY = (
#     0x0,
#     0x0,
# )
# TODO: Add clientLockboxKey


def get_hwid_from_session_id(session_id):
    hwid_b64 = [i[5:] for i in session_id.split(";") if "Hwid" in i][0]
    return b64decode(hwid_b64)


def get_hwid_from_genuine_ticket(xml_str):
    root = ET.fromstring(xml_str)
    properties = root.findtext(
        ".//{http://www.microsoft.com/DRM/SL/GenuineAuthorization/1.0}properties"
    )
    session_id_b64 = properties[10:].split(";")[0]
    session_id = b64decode(session_id_b64).decode("utf-16-le")
    return get_hwid_from_session_id(session_id)


def get_hwid_from_license_xml(xml_str):
    root = ET.fromstring(xml_str)
    migrated_license_data = root.findtext(
        "{urn:schemas-microsoft-com:windows:store:licensing:ls}MigratedLicenseData"
    )
    genuine_ticket_str = b64decode(migrated_license_data).decode()
    return get_hwid_from_genuine_ticket(genuine_ticket_str)


def get_hwid_from_clipup():
    """Needs admin access, uses ClipUp to generate a license from a BIOS key.
    Manually use a generic key to make it work without actually having a valid bios license
    Returns the binary HWID"""
    print("Running clipup")
    os.system(f"ClipUp -v -d -k {GENERIC_PRODUCT_KEY} .")
    if files := os.listdir("Migration"):
        with open(f"Migration/{files[0]}") as f:
            hwid = get_hwid_from_license_xml(f.read())
        os.remove(f"Migration/{files[0]}")
        os.rmdir("Migration")
        return hwid
    else:
        raise RuntimeError(
            "Clipup failed to create files in Migration folder, probably wasn't run as admin!"
        )


def get_pfn():
    key = OpenKey(HKEY_LOCAL_MACHINE, "SYSTEM\CurrentControlSet\Control\ProductOptions")
    return QueryValueEx(key, "OSProductPfn")[0]


def create_properties(
    hwid, pfn, OSMajorVersion="10", timestamp="TimeStampClient=0000-00-00T00:00:00Z"
):
    session_id_str = f"OSMajorVersion={OSMajorVersion};Hwid={b64encode(hwid).decode()};Pfn={pfn};DownlevelGenuineState=1;"
    return (
        "SessionId="
        + b64encode(session_id_str.encode("utf-16-le")).decode()
        + f";{timestamp}"
    )


def sign_properties(properties, key):
    digest = sha256(properties.encode("utf-8")).hexdigest()
    m = "0001" + "F" * 404 + "003031300d060960864801650304020105000420" + digest
    return pow(int(m, 16), key[0], key[1])


def raw_to_blob_str(public_key):
    return b64encode(BLOB_HEADER + public_key.to_bytes(256, "little")).decode()


def create_xml(properties_string, key):
    root = ET.Element(
        "genuineAuthorization",
        {"xmlns": "http://www.microsoft.com/DRM/SL/GenuineAuthorization/1.0"},
    )
    version = ET.Element("version")
    version.text = "1.0"
    root.append(version)

    genuine_properties = ET.Element("genuineProperties", {"origin": "sppclient"})

    properties = ET.Element("properties")

    properties.text = properties_string

    genuine_properties.append(properties)

    signatures = ET.Element("signatures")

    b64key = raw_to_blob_str(key[1])

    signature = ET.Element(
        "signature", {"name": "downlevelGTkey", "method": "rsa-sha256", "key": b64key}
    )

    sig = sign_properties(properties_string, key)

    signature.text = b64encode(sig.to_bytes(256, "big")).decode()

    signatures.append(signature)

    genuine_properties.append(signatures)

    root.append(genuine_properties)

    return (
        "<?xml version='1.0' encoding='utf-8'?>"
        + ET.tostring(root, method="xml").decode()
    )


def activate(key, hwid=None, pfn=None):
    if hwid is None:
        hwid = get_hwid_from_clipup()
    if pfn is None:
        pfn = get_pfn()
    properties = create_properties(hwid, pfn)
    ticket = create_xml(properties, key)
    with open(
        "GenuineTicket.xml",
        "w",
    ) as f:
        f.write(ticket)
    print("activating")
    os.system("ClipUp -v -o -altto .")
    return os.system(f"cscript {os.getenv('SYSTEMROOT')}\System32\slmgr.vbs /ato")


if __name__ == "__main__":
    try:
        from keys import CLIPUP_KEY, GATHEROSSTATE_KEY
    except ImportError:
        print("You need to create a keys.py file!")
        raise
    if activate(GATHEROSSTATE_KEY):
        raise RuntimeError("Failed to activate system!")
