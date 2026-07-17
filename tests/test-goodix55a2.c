/*
 * Goodix GF3206 pure helper tests
 *
 * Copyright (C) 2026 Elvin Starry
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <glib.h>

#include "drivers/goodix55a2.h"
#include "fp-device.h"
#include "fpi-assembling.h"
#include "fpi-byte-utils.h"
#include "fpi-image.h"

static void
pack_group (const guint16 *pixels,
            guint8        *packed)
{
  guint16 p0 = pixels[0] & 0xfff;
  guint16 p1 = pixels[1] & 0xfff;
  guint16 p2 = pixels[2] & 0xfff;
  guint16 p3 = pixels[3] & 0xfff;

  packed[0] = ((p1 & 0x0f) << 4) | (p0 >> 8);
  packed[1] = p0 & 0xff;
  packed[2] = p2 & 0xff;
  packed[3] = p1 >> 4;
  packed[4] = p3 >> 4;
  packed[5] = ((p2 >> 8) & 0x0f) | ((p3 & 0x0f) << 4);
}

static void
pack_row (const guint16 *pixels,
          guint8        *packed,
          guint8         padding0,
          guint8         padding1)
{
  for (guint offset = 0; offset < 52; offset += 4)
    pack_group (pixels + offset, packed + offset / 4 * 6);

  {
    guint16 tail[4] = { pixels[52], pixels[53], 0xabc, 0xdef };
    guint8 tail_packed[6];

    pack_group (tail, tail_packed);
    memcpy (packed + 78, tail_packed, 4);
  }
  packed[82] = padding0;
  packed[83] = padding1;
}

static void
test_endpoint_selection (void)
{
  static const guint8 poc_order[] = { 0x01, 0x82 };
  static const guint8 reversed_and_changed[] = { 0x84, 0x03 };
  static const guint8 ambiguous[] = { 0x01, 0x02, 0x82 };
  guint8 bulk_in = 0;
  guint8 bulk_out = 0;
  g_autoptr(GError) error = NULL;

  g_assert_true (goodix55a2_select_bulk_endpoints (
    poc_order, G_N_ELEMENTS (poc_order), &bulk_in, &bulk_out, &error));
  g_assert_no_error (error);
  g_assert_cmphex (bulk_in, ==, 0x82);
  g_assert_cmphex (bulk_out, ==, 0x01);

  g_assert_true (goodix55a2_select_bulk_endpoints (
    reversed_and_changed, G_N_ELEMENTS (reversed_and_changed),
    &bulk_in, &bulk_out, &error));
  g_assert_no_error (error);
  g_assert_cmphex (bulk_in, ==, 0x84);
  g_assert_cmphex (bulk_out, ==, 0x03);

  g_assert_false (goodix55a2_select_bulk_endpoints (
    ambiguous, G_N_ELEMENTS (ambiguous), &bulk_in, &bulk_out, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
}

static void
test_command_builder (void)
{
  static const guint8 payload[] = { 0x00, 0x00 };
  g_autoptr(GByteArray) packet =
    goodix55a2_build_command (0xa8, payload, sizeof (payload));
  static const guint8 expected[] = {
    0xa0, 0x06, 0x00, 0xa6, 0xa8, 0x03, 0x00, 0x00, 0x00, 0xff,
  };

  g_assert_cmpuint (packet->len, ==, 64);
  g_assert_cmpmem (packet->data, sizeof (expected), expected, sizeof (expected));
  for (guint i = sizeof (expected); i < packet->len; i++)
    g_assert_cmpuint (packet->data[i], ==, 0);
}

static void
test_reply_parser (void)
{
  static const guint8 reply[] = {
    0xa0, 0x1b, 0x00, 0xbb, 0xa8, 0x18, 0x00,
    'G', 'F', '3', '2', '0', '6', '_', 'R', 'T', 'S', 'E', 'C', '_',
    'A', 'P', 'P', '_', '1', '0', '0', '5', '6', 0x00, 0x17,
  };
  const guint8 *payload = NULL;
  gsize payload_len = 0;
  g_autoptr(GError) error = NULL;

  g_assert_true (goodix55a2_parse_command_reply (
    reply, sizeof (reply), 0xa8, &payload, &payload_len, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (payload_len, ==, 23);
  g_assert_cmpmem (payload, payload_len,
                   "GF3206_RTSEC_APP_10056", payload_len);

  {
    guint8 invalid[sizeof (reply)];

    memcpy (invalid, reply, sizeof (reply));
    invalid[3]++;
    g_assert_false (goodix55a2_parse_command_reply (
      invalid, sizeof (invalid), 0xa8, NULL, NULL, &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
    g_clear_error (&error);
  }

  {
    static const guint8 image_reply[] = {
      0xb2, 0x0c, 0x00, 0xbe,
      0x00, 0x20, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xaa, 0xbb, 0xcc,
    };
    g_assert_true (goodix55a2_parse_image_reply (
      image_reply, sizeof (image_reply), &payload, &payload_len, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (payload_len, ==, 3);
    g_assert_cmpmem (payload, payload_len, "\xaa\xbb\xcc", 3);
  }
}

static void
test_command_ack_parser (void)
{
  static const guint8 established_ack[] = {
    0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa8, 0x01, 0x4e,
  };
  static const guint8 pre_tls_ack[] = {
    0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa8, 0x03, 0x4c,
  };
  static const guint8 invalid_ack[] = {
    0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa8, 0x02, 0x4d,
  };
  g_autoptr(GError) error = NULL;

  g_assert_true (goodix55a2_parse_command_ack (
    established_ack, sizeof (established_ack), 0xa8, &error));
  g_assert_no_error (error);

  g_assert_true (goodix55a2_parse_command_ack (
    pre_tls_ack, sizeof (pre_tls_ack), 0xa8, &error));
  g_assert_no_error (error);

  g_assert_false (goodix55a2_parse_command_ack (
    invalid_ack, sizeof (invalid_ack), 0xa8, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
}

static void
test_unpack_frame (void)
{
  g_autofree guint8 *packed = g_malloc (GOODIX55A2_PACKED_FRAME_SIZE);
  g_autofree guint16 *expected = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  g_autofree guint16 *actual = g_new0 (guint16, GOODIX55A2_IMAGE_PIXELS);
  g_autoptr(GError) error = NULL;

  for (guint wire_y = 0; wire_y < GOODIX55A2_IMAGE_WIDTH; wire_y++)
    {
      guint16 row[GOODIX55A2_IMAGE_HEIGHT];

      for (guint x = 0; x < GOODIX55A2_IMAGE_HEIGHT; x++)
        {
          row[x] = (wire_y * GOODIX55A2_IMAGE_HEIGHT + x) & 0xfff;
          expected[x * GOODIX55A2_IMAGE_WIDTH + wire_y] = row[x];
        }
      pack_row (row, packed + wire_y * GOODIX55A2_WIRE_ROW_BYTES,
                0xa5, 0x5a);
    }

  g_assert_true (goodix55a2_unpack_frame (packed,
                                          GOODIX55A2_PACKED_FRAME_SIZE,
                                          actual, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (actual, GOODIX55A2_IMAGE_PIXELS * sizeof (*actual),
                   expected, GOODIX55A2_IMAGE_PIXELS * sizeof (*expected));

  for (guint wire_y = 0; wire_y < GOODIX55A2_IMAGE_WIDTH; wire_y++)
    {
      packed[wire_y * GOODIX55A2_WIRE_ROW_BYTES + 82] = 0xff;
      packed[wire_y * GOODIX55A2_WIRE_ROW_BYTES + 83] = 0xff;
    }
  memset (actual, 0, GOODIX55A2_IMAGE_PIXELS * sizeof (*actual));
  g_assert_true (goodix55a2_unpack_frame (packed,
                                          GOODIX55A2_PACKED_FRAME_SIZE,
                                          actual, &error));
  g_assert_cmpmem (actual, GOODIX55A2_IMAGE_PIXELS * sizeof (*actual),
                   expected, GOODIX55A2_IMAGE_PIXELS * sizeof (*expected));
}

static void
test_swipe_assembly (void)
{
  enum { FRAME_COUNT = 4, DELTA_Y = 6 };
  const guint source_height = GOODIX55A2_IMAGE_HEIGHT +
                              (FRAME_COUNT - 1) * DELTA_Y;
  g_autofree guint8 *source = g_new (guint8,
                                     GOODIX55A2_IMAGE_WIDTH * source_height);
  g_autoptr(FpImage) image = NULL;
  GSList *frames = NULL;
  guint32 random = 0x55a227c6;

  for (guint i = 0; i < GOODIX55A2_IMAGE_WIDTH * source_height; i++)
    {
      random = random * 1664525 + 1013904223;
      source[i] = random >> 24;
    }

  for (guint frame_index = 0; frame_index < FRAME_COUNT; frame_index++)
    {
      struct fpi_frame *frame = g_malloc0 (sizeof (*frame) +
                                           GOODIX55A2_IMAGE_PIXELS);

      for (guint y = 0; y < GOODIX55A2_IMAGE_HEIGHT; y++)
        memcpy (frame->data + y * GOODIX55A2_IMAGE_WIDTH,
                source + (y + frame_index * DELTA_Y) *
                  GOODIX55A2_IMAGE_WIDTH,
                GOODIX55A2_IMAGE_WIDTH);
      frames = g_slist_append (frames, frame);
    }

  image = goodix55a2_assemble_swipe (frames);
  g_assert_nonnull (image);
  g_assert_cmpuint (image->width, ==, GOODIX55A2_ASSEMBLED_WIDTH);
  g_assert_cmpuint (image->height, ==, source_height);
  for (GSList *item = frames->next; item; item = item->next)
    {
      struct fpi_frame *frame = item->data;

      g_assert_cmpint (ABS (frame->delta_x), ==, 0);
      g_assert_cmpint (ABS (frame->delta_y), ==, DELTA_Y);
    }

  frames = g_slist_reverse (frames);
  g_clear_object (&image);
  image = goodix55a2_assemble_swipe (frames);
  g_assert_nonnull (image);
  g_assert_cmpuint (image->width, ==, GOODIX55A2_ASSEMBLED_WIDTH);
  g_assert_cmpuint (image->height, ==, source_height);

  g_slist_free_full (frames, g_free);
}

static void
test_cached_calibration_validation (void)
{
  g_autofree guint16 *baseline = g_new (guint16,
                                        GOODIX55A2_IMAGE_PIXELS);
  g_autofree guint16 *frames = g_new (
    guint16, GOODIX55A2_CALIBRATION_VALIDATE_FRAMES *
      GOODIX55A2_IMAGE_PIXELS);
  static const gint close_offsets[] = { -4, 0, 4 };
  static const gint drifted_offsets[] = { 30, 32, 34 };
  g_autoptr(GError) error = NULL;

  for (guint pixel = 0; pixel < GOODIX55A2_IMAGE_PIXELS; pixel++)
    baseline[pixel] = 2800 + pixel % GOODIX55A2_IMAGE_WIDTH;

  for (guint frame = 0; frame < G_N_ELEMENTS (close_offsets); frame++)
    for (guint pixel = 0; pixel < GOODIX55A2_IMAGE_PIXELS; pixel++)
      frames[frame * GOODIX55A2_IMAGE_PIXELS + pixel] =
        baseline[pixel] + close_offsets[frame];

  g_assert_true (goodix55a2_calibration_is_stable (
    frames, GOODIX55A2_CALIBRATION_VALIDATE_FRAMES, baseline, 5.0, &error));
  g_assert_no_error (error);

  for (guint frame = 0; frame < G_N_ELEMENTS (drifted_offsets); frame++)
    for (guint pixel = 0; pixel < GOODIX55A2_IMAGE_PIXELS; pixel++)
      frames[frame * GOODIX55A2_IMAGE_PIXELS + pixel] =
        baseline[pixel] + drifted_offsets[frame];

  g_assert_false (goodix55a2_calibration_is_stable (
    frames, GOODIX55A2_CALIBRATION_VALIDATE_FRAMES, baseline, 5.0, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
}

static void
test_calibration_and_flat_field (void)
{
  g_autofree guint16 *frames = g_new (guint16,
                                      5 * GOODIX55A2_IMAGE_PIXELS);
  g_autofree guint16 *baseline = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  g_autofree guint16 *raw = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  g_autofree guint16 *kr = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  g_autofree guint16 *corrected = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  static const gint offsets[] = { -5, 0, 4, 1, 40 };
  g_autoptr(GError) error = NULL;

  for (guint frame = 0; frame < G_N_ELEMENTS (offsets); frame++)
    for (guint pixel = 0; pixel < GOODIX55A2_IMAGE_PIXELS; pixel++)
      frames[frame * GOODIX55A2_IMAGE_PIXELS + pixel] =
        CLAMP (2800 + (gint) (pixel % GOODIX55A2_IMAGE_WIDTH) + offsets[frame],
               0, 4095);

  g_assert_true (goodix55a2_build_calibration (
    frames, G_N_ELEMENTS (offsets), baseline, &error));
  g_assert_no_error (error);
  g_assert_true (goodix55a2_calibration_is_stable (
    frames, G_N_ELEMENTS (offsets), baseline, 25.0, &error));
  g_assert_no_error (error);
  for (guint pixel = 0; pixel < GOODIX55A2_IMAGE_PIXELS; pixel++)
    {
      g_assert_cmpuint (baseline[pixel], ==,
                        2801 + (pixel % GOODIX55A2_IMAGE_WIDTH));
      raw[pixel] = baseline[pixel] - 101;
      kr[pixel] = GOODIX55A2_Q13_ONE * 2;
    }

  goodix55a2_flat_field (raw, baseline, kr, corrected);
  for (guint pixel = 0; pixel < GOODIX55A2_IMAGE_PIXELS; pixel++)
    g_assert_cmpuint (corrected[pixel], ==, 51);

  for (guint frame = 2; frame < G_N_ELEMENTS (offsets); frame++)
    for (guint pixel = 0; pixel < GOODIX55A2_IMAGE_PIXELS; pixel++)
      frames[frame * GOODIX55A2_IMAGE_PIXELS + pixel] += 100;
  g_assert_false (goodix55a2_calibration_is_stable (
    frames, G_N_ELEMENTS (offsets), baseline, 25.0, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
}

static void
test_real_fixture (void)
{
  const char *fixture_dir = g_getenv ("GOODIX55A2_FIXTURE_DIR");
  g_autofree char *packed_path = NULL;
  g_autofree char *native_path = NULL;
  g_autofree char *packed = NULL;
  g_autofree char *native = NULL;
  g_autofree guint16 *actual = NULL;
  gsize packed_len = 0;
  gsize native_len = 0;
  g_autoptr(GError) error = NULL;

  if (!fixture_dir)
    {
      g_test_skip ("Authenticated GF3206 fixture is not available");
      return;
    }

  packed_path = g_build_filename (fixture_dir, "frame_390.packed.bin", NULL);
  native_path = g_build_filename (fixture_dir, "frame_390.native_u16le.bin", NULL);
  g_assert_true (g_file_get_contents (packed_path, &packed, &packed_len, &error));
  g_assert_no_error (error);
  g_assert_true (g_file_get_contents (native_path, &native, &native_len, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (native_len, ==,
                    GOODIX55A2_IMAGE_PIXELS * sizeof (guint16));

  actual = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  g_assert_true (goodix55a2_unpack_frame ((const guint8 *) packed, packed_len,
                                          actual, &error));
  g_assert_no_error (error);

  for (guint y = 0; y < GOODIX55A2_IMAGE_HEIGHT; y++)
    for (guint x = 0; x < GOODIX55A2_IMAGE_WIDTH; x++)
      g_assert_cmpuint (actual[y * GOODIX55A2_IMAGE_WIDTH + x], ==,
                        FP_READ_UINT16_LE (
                          (const guint8 *) native +
                          2 * (x * GOODIX55A2_IMAGE_HEIGHT + y)));

  g_assert_cmpuint (actual[GOODIX55A2_IMAGE_WIDTH + 1], ==, 1390);
  g_assert_cmpuint (actual[2 * GOODIX55A2_IMAGE_WIDTH + 1], ==, 1842);
}

static void
test_normalize (void)
{
  g_autofree guint16 *corrected = g_new0 (guint16,
                                          GOODIX55A2_IMAGE_PIXELS);
  g_autofree guint8 *image = g_new0 (guint8, GOODIX55A2_IMAGE_PIXELS);

  for (guint y = 1; y + 1 < GOODIX55A2_IMAGE_HEIGHT; y++)
    for (guint x = 1; x + 1 < GOODIX55A2_IMAGE_WIDTH; x++)
      corrected[y * GOODIX55A2_IMAGE_WIDTH + x] = x + y;

  goodix55a2_normalize (corrected, image);
  g_assert_cmpuint (image[0], ==, 0);
  g_assert_cmpuint (image[(GOODIX55A2_IMAGE_HEIGHT - 1) *
                          GOODIX55A2_IMAGE_WIDTH], ==, 0);
  g_assert_cmpuint (image[GOODIX55A2_IMAGE_WIDTH + 1], ==, 0);
  g_assert_cmpuint (image[(GOODIX55A2_IMAGE_HEIGHT - 2) *
                          GOODIX55A2_IMAGE_WIDTH +
                          GOODIX55A2_IMAGE_WIDTH - 2], ==, 255);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/goodix55a2/protocol/command-builder",
                   test_command_builder);
  g_test_add_func ("/goodix55a2/protocol/endpoint-selection",
                   test_endpoint_selection);
  g_test_add_func ("/goodix55a2/protocol/reply-parser",
                   test_reply_parser);
  g_test_add_func ("/goodix55a2/protocol/command-ack-parser",
                   test_command_ack_parser);
  g_test_add_func ("/goodix55a2/image/unpack", test_unpack_frame);
  g_test_add_func ("/goodix55a2/image/swipe-assembly",
                   test_swipe_assembly);
  g_test_add_func ("/goodix55a2/image/calibration-flat-field",
                   test_calibration_and_flat_field);
  g_test_add_func ("/goodix55a2/image/calibration-cache-validation",
                   test_cached_calibration_validation);
  g_test_add_func ("/goodix55a2/image/normalize", test_normalize);
  g_test_add_func ("/goodix55a2/image/real-fixture", test_real_fixture);

  return g_test_run ();
}
