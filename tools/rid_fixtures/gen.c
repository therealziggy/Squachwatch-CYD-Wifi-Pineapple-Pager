/* tools/rid_fixtures/gen.c — build Remote ID WiFi frames with opendroneid-core-c and write a
 * LINKTYPE_IEEE802_11_RADIO pcap. Dev box only; never installed on the Pager. Frames go to a FILE
 * only: nothing here touches a radio. See build.sh.
 * Usage: gen <kind> <out.pcap>
 *   kind = beacon | nan | parrot | multi | unknowns | equator | order | quiet | truncated */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "opendroneid.h"

static void put32(FILE *f, uint32_t v) { fwrite(&v, 4, 1, f); }
static void put16(FILE *f, uint16_t v) { fwrite(&v, 2, 1, f); }

/* one packet record: radiotap {version 0, pad 0, length 9, present = dBm antenna signal, signal}, then the frame */
static void put_packet(FILE *f, uint32_t ts, const uint8_t *frame, int flen, int8_t sig) {
    uint8_t rtap[9] = {0, 0, 9, 0, 0x20, 0, 0, 0, (uint8_t)sig};
    uint32_t caplen = (uint32_t)(sizeof(rtap) + flen);
    put32(f, ts); put32(f, 0); put32(f, caplen); put32(f, caplen);
    fwrite(rtap, sizeof(rtap), 1, f); fwrite(frame, flen, 1, f);
}
static FILE *open_pcap(const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    put32(f, 0xa1b2c3d4); put16(f, 2); put16(f, 4); put32(f, 0); put32(f, 0);
    put32(f, 262144); put32(f, 127);                 /* snaplen, LINKTYPE_IEEE802_11_RADIO */
    return f;
}

/* a made-up drone: serial, airframe, airborne location, live pilot location, operator id */
static void drone(ODID_UAS_Data *d, const char *serial, double lat, double lon) {
    memset(d, 0, sizeof(*d));
    odid_initUasData(d);
    d->BasicID[0].UAType = ODID_UATYPE_HELICOPTER_OR_MULTIROTOR;
    d->BasicID[0].IDType = ODID_IDTYPE_SERIAL_NUMBER;
    strncpy(d->BasicID[0].UASID, serial, ODID_ID_SIZE);
    d->BasicIDValid[0] = 1;
    d->Location.Status = ODID_STATUS_AIRBORNE;
    d->Location.Direction = 215.0f;
    d->Location.SpeedHorizontal = 12.0f;
    d->Location.SpeedVertical = 3.0f;
    d->Location.Latitude = lat; d->Location.Longitude = lon;
    d->Location.AltitudeGeo = 520.0f; d->Location.Height = 87.0f;
    d->Location.HeightType = ODID_HEIGHT_REF_OVER_TAKEOFF;
    d->LocationValid = 1;
    d->System.OperatorLocationType = ODID_OPERATOR_LOCATION_TYPE_LIVE_GNSS;
    d->System.OperatorLatitude = 47.398000; d->System.OperatorLongitude = 8.541020;
    d->SystemValid = 1;
    d->OperatorID.OperatorIdType = 0;
    strncpy(d->OperatorID.OperatorId, "SWTESTOPERATOR01", ODID_ID_SIZE);
    d->OperatorIDValid = 1;
}

static int beacon(const ODID_UAS_Data *d, const char *mac, const char *ssid, uint8_t *buf, size_t n) {
    int l = odid_wifi_build_message_pack_beacon_frame(d, mac, ssid, strlen(ssid), 100, 0, buf, n);
    if (l < 0) { fprintf(stderr, "beacon build failed %d\n", l); exit(1); }
    /* The library stamps this machine's uptime into the beacon's timestamp (the 8 bytes after the
     * 24-byte header). Zero it: the fixtures then come out the same on every run and say nothing
     * about the machine that made them. Nothing reads this field. */
    memset(buf + 24, 0, 8);
    return l;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: gen <kind> <out.pcap>\n"); return 2; }
    const char *kind = argv[1];
    const char *mac1 = "\x80\xE1\x26\xAA\xBB\xCC", *mac2 = "\x80\xE1\x26\x11\x22\x33";
    ODID_UAS_Data d;
    uint8_t fr[1024]; int n;
    FILE *f = open_pcap(argv[2]);

    if (!strcmp(kind, "quiet")) {              /* an ordinary beacon, no Remote ID: the frame-parser control */
        static const uint8_t q[] = {0x80,0,0,0, 0xff,0xff,0xff,0xff,0xff,0xff, 0x02,0x00,0x00,0x00,0x00,0x01,
            0x02,0x00,0x00,0x00,0x00,0x01, 0,0, 0,0,0,0,0,0,0,0, 0x64,0, 0x01,0x04,
            0x00,0x06,'S','W','T','E','S','T', 0x01,0x01,0x8c};
        put_packet(f, 1700000000, q, sizeof(q), -55); fclose(f); return 0;
    }
    drone(&d, "0000FSWTEST000000001", 47.397760, 8.545420);
    if (!strcmp(kind, "unknowns")) {           /* every value the standard marks "unknown / no value" */
        d.Location.Latitude = 0; d.Location.Longitude = 0;
        d.Location.AltitudeGeo = -1000; d.Location.Height = -1000;
        d.Location.SpeedHorizontal = 255; d.Location.SpeedVertical = 63; d.Location.Direction = 361;
        d.System.OperatorLatitude = 0; d.System.OperatorLongitude = 0;
    }
    if (!strcmp(kind, "equator"))              /* latitude exactly 0 is a real place when longitude is not 0 */
        d.Location.Latitude = 0;
    if (!strcmp(kind, "nan")) {
        n = odid_wifi_build_message_pack_nan_action_frame(&d, mac1, 0, fr, sizeof(fr));
        if (n < 0) { fprintf(stderr, "nan build failed %d\n", n); return 1; }
        put_packet(f, 1700000000, fr, n, -47); fclose(f); return 0;
    }
    n = beacon(&d, mac1, "TEST-DRONE", fr, sizeof(fr));
    if (!strcmp(kind, "parrot")) {             /* the same element under Parrot's OUI (and a different type byte) */
        for (int i = 36; i + 6 < n; i++)
            if (fr[i] == 0xdd && fr[i+2] == 0xfa && fr[i+3] == 0x0b && fr[i+4] == 0xbc) {
                fr[i+2] = 0x90; fr[i+3] = 0x3a; fr[i+4] = 0xe6; fr[i+5] = 0x00; break;
            }
    }
    if (!strcmp(kind, "order")) {              /* Order bit set: 4 bytes of HT control after the 24-byte header */
        uint8_t o[1024];
        memcpy(o, fr, 24); o[1] |= 0x80; memset(o + 24, 0, 4); memcpy(o + 28, fr + 24, n - 24);
        put_packet(f, 1700000000, o, n + 4, -47); fclose(f); return 0;
    }
    if (!strcmp(kind, "multi")) {              /* a WEAKER drone heard FIRST, so "strongest first" is not arrival order */
        ODID_UAS_Data d2; uint8_t f2[1024];
        drone(&d2, "0000FSWTEST000000002", 48.100000, 9.200000);
        int l2 = beacon(&d2, mac2, "DRONE-TWO", f2, sizeof(f2));
        put_packet(f, 1699999999, f2, l2, -61);
    }
    if (!strcmp(kind, "truncated")) n -= 40;   /* cut short inside the message pack */
    put_packet(f, 1700000000, fr, n, -47);
    fclose(f);
    return 0;
}
