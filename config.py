"""git config"""
CAPABILITY_ATOMIC = b"atomic"
CAPABILITY_DEEPEN_SINCE = b"deepen-since"
CAPABILITY_DEEPEN_NOT = b"deepen-not"
CAPABILITY_DEEPEN_RELATIVE = b"deepen-relative"
CAPABILITY_DELETE_REFS = b"delete-refs"
CAPABILITY_INCLUDE_TAG = b"include-tag"
CAPABILITY_MULTI_ACK = b"multi_ack"
CAPABILITY_MULTI_ACK_DETAILED = b"multi_ack_detailed"
CAPABILITY_NO_DONE = b"no-done"
CAPABILITY_NO_PROGRESS = b"no-progress"
CAPABILITY_OFS_DELTA = b"ofs-delta"
CAPABILITY_QUIET = b"quiet"
CAPABILITY_REPORT_STATUS = b"report-status"
CAPABILITY_SHALLOW = b"shallow"
CAPABILITY_SIDE_BAND = b"side-band"
CAPABILITY_SIDE_BAND_64K = b"side-band-64k"
CAPABILITY_THIN_PACK = b"thin-pack"
CAPABILITY_AGENT = b"agent"
CAPABILITY_SYMREF = b"symref"
CAPABILITY_ALLOW_TIP_SHA1_IN_WANT = b"allow-tip-sha1-in-want"
CAPABILITY_ALLOW_REACHABLE_SHA1_IN_WANT = b"allow-reachable-sha1-in-want"

COMMON_CAPABILITIES = [CAPABILITY_OFS_DELTA, CAPABILITY_SIDE_BAND_64K]
UPLOAD_CAPABILITIES = [
    CAPABILITY_THIN_PACK,
    CAPABILITY_MULTI_ACK,
    CAPABILITY_MULTI_ACK_DETAILED,
    CAPABILITY_SHALLOW,
] + COMMON_CAPABILITIES
RECEIVE_CAPABILITIES = [
    CAPABILITY_REPORT_STATUS,
    CAPABILITY_DELETE_REFS,
] + COMMON_CAPABILITIES

ZERO_SHA = b"0" * 40

GIT_VERSIONS = [
    b"0.99.9n",
    b"1.0.13",
    b"1.1.6",
    b"1.2.6",
    b"1.3.3",
    b"1.4.4.5",
    b"1.5.6.6",
    b"1.6.6.3",
    b"1.7.12.4",
    b"1.8.5.6",
    b"1.9.5",
    b"2.0.5",
    b"2.1.4",
    b"2.2.3",
    b"2.3.10",
    b"2.4.12",
    b"2.5.6",
    b"2.6.7",
    b"2.7.6",
    b"2.8.6",
    b"2.9.5",
    b"2.10.5",
    b"2.11.4",
    b"2.12.5",
    b"2.13.7",
    b"2.14.6",
    b"2.15.4",
    b"2.16.6",
    b"2.17.6",
    b"2.18.5",
    b"2.19.6",
    b"2.20.5",
    b"2.21.4",
    b"2.22.5",
    b"2.23.4",
    b"2.24.4",
    b"2.25.5",
    b"2.26.3",
    b"2.27.1",
    b"2.28.1",
    b"2.29.3",
    b"2.30.2",
    b"2.31.1",
    b"2.33.1",
]
