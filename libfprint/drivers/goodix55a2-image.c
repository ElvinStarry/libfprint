/*
 * Goodix GF3206 image and protocol helpers
 *
 * Copyright (C) 2026 Elvin Starry
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "goodix55a2.h"

#include "fpi-assembling.h"
#include "fpi-byte-utils.h"
#include "fpi-device.h"

#include <math.h>
#include <string.h>

#define GOODIX55A2_COMMAND_TYPE 0xa0
#define GOODIX55A2_TLS_TYPE     0xb0
#define GOODIX55A2_IMAGE_TYPE   0xb2
#define GOODIX55A2_IMAGE_HEADER_SIZE 13

gboolean
goodix55a2_select_bulk_endpoints (const guint8 *addresses,
                                  gsize         address_count,
                                  guint8       *bulk_in,
                                  guint8       *bulk_out,
                                  GError      **error)
{
  guint8 selected_in = 0;
  guint8 selected_out = 0;

  for (gsize i = 0; i < address_count; i++)
    {
      guint8 address = addresses[i];
      guint8 *selected = address & 0x80 ? &selected_in : &selected_out;

      if ((address & 0x0f) == 0 || *selected != 0)
        {
          g_set_error_literal (error, FP_DEVICE_ERROR,
                               FP_DEVICE_ERROR_NOT_SUPPORTED,
                               "GF3206 USB endpoints are ambiguous");
          return FALSE;
        }
      *selected = address;
    }

  if (!selected_in || !selected_out)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR,
                           FP_DEVICE_ERROR_NOT_SUPPORTED,
                           "GF3206 USB bulk endpoints are missing");
      return FALSE;
    }

  *bulk_in = selected_in;
  *bulk_out = selected_out;
  return TRUE;
}

static guint8
sum8 (const guint8 *data,
      gsize         length)
{
  guint sum = 0;

  for (gsize i = 0; i < length; i++)
    sum += data[i];

  return sum & 0xff;
}

static void
pad64 (GByteArray *packet)
{
  gsize padded = (packet->len + 63) & ~((gsize) 63);
  gsize old_length = packet->len;

  g_byte_array_set_size (packet, padded);
  memset (packet->data + old_length, 0, padded - old_length);
}

GByteArray *
goodix55a2_build_command (guint8        command,
                          const guint8 *payload,
                          gsize         payload_len)
{
  g_autoptr(GByteArray) inner = NULL;
  GByteArray *packet;
  guint8 header[4];
  guint8 checksum;

  g_return_val_if_fail (payload_len <= G_MAXUINT16 - 1, NULL);
  g_return_val_if_fail (payload != NULL || payload_len == 0, NULL);

  inner = g_byte_array_sized_new (payload_len + 4);
  g_byte_array_append (inner, &command, 1);
  header[0] = (payload_len + 1) & 0xff;
  header[1] = (payload_len + 1) >> 8;
  g_byte_array_append (inner, header, 2);
  g_byte_array_append (inner, payload, payload_len);
  checksum = (0xaa - sum8 (inner->data, inner->len)) & 0xff;
  g_byte_array_append (inner, &checksum, 1);

  header[0] = GOODIX55A2_COMMAND_TYPE;
  header[1] = inner->len & 0xff;
  header[2] = inner->len >> 8;
  header[3] = sum8 (header, 3);

  packet = g_byte_array_sized_new (inner->len + sizeof (header) + 63);
  g_byte_array_append (packet, header, sizeof (header));
  g_byte_array_append (packet, inner->data, inner->len);
  pad64 (packet);

  return packet;
}

GByteArray *
goodix55a2_build_tls (const guint8 *payload,
                      gsize         payload_len)
{
  GByteArray *packet;
  guint8 header[4];

  g_return_val_if_fail (payload_len <= G_MAXUINT16, NULL);
  g_return_val_if_fail (payload != NULL || payload_len == 0, NULL);

  header[0] = GOODIX55A2_TLS_TYPE;
  header[1] = payload_len & 0xff;
  header[2] = payload_len >> 8;
  header[3] = sum8 (header, 3);

  packet = g_byte_array_sized_new (payload_len + sizeof (header) + 63);
  g_byte_array_append (packet, header, sizeof (header));
  g_byte_array_append (packet, payload, payload_len);
  pad64 (packet);

  return packet;
}

gboolean
goodix55a2_validate_container (const guint8 *data,
                               gsize         length,
                               guint8        expected_type,
                               GError      **error)
{
  guint16 payload_len;

  if (length < 4)
    goto invalid_length;
  if (data[0] != expected_type)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected Goodix container type 0x%02x (expected 0x%02x)",
                   data[0], expected_type);
      return FALSE;
    }
  if (sum8 (data, 3) != data[3])
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "Invalid Goodix container header checksum");
      return FALSE;
    }

  payload_len = FP_READ_UINT16_LE (data + 1);
  if (length != (gsize) payload_len + 4)
    goto invalid_length;

  return TRUE;

invalid_length:
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "Invalid Goodix container length %" G_GSIZE_FORMAT, length);
  return FALSE;
}

gboolean
goodix55a2_parse_command_reply (const guint8  *data,
                                gsize          length,
                                guint8         expected_command,
                                const guint8 **payload,
                                gsize         *payload_len,
                                GError       **error)
{
  guint16 inner_len;

  if (length < 8)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "Goodix command reply is too short");
      return FALSE;
    }
  if (!goodix55a2_validate_container (data, length,
                                      GOODIX55A2_COMMAND_TYPE, error))
    return FALSE;

  inner_len = FP_READ_UINT16_LE (data + 5);
  if (inner_len < 1 || (gsize) inner_len + 7 != length)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "Invalid Goodix command reply length");
      return FALSE;
    }
  if (data[4] != expected_command)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected Goodix reply command 0x%02x (expected 0x%02x)",
                   data[4], expected_command);
      return FALSE;
    }
  if (sum8 (data + 4, inner_len + 3) != 0xaa)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "Invalid Goodix command reply checksum");
      return FALSE;
    }

  if (payload)
    *payload = data + 7;
  if (payload_len)
    *payload_len = inner_len - 1;
  return TRUE;
}

gboolean
goodix55a2_parse_tls_reply (const guint8  *data,
                            gsize          length,
                            const guint8 **payload,
                            gsize         *payload_len,
                            GError       **error)
{
  if (!goodix55a2_validate_container (data, length,
                                      GOODIX55A2_TLS_TYPE, error))
    return FALSE;

  *payload = data + 4;
  *payload_len = length - 4;
  return TRUE;
}

gboolean
goodix55a2_parse_image_reply (const guint8  *data,
                              gsize          length,
                              const guint8 **payload,
                              gsize         *payload_len,
                              GError       **error)
{
  if (!goodix55a2_validate_container (data, length,
                                      GOODIX55A2_IMAGE_TYPE, error))
    return FALSE;
  if (length <= GOODIX55A2_IMAGE_HEADER_SIZE)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "Goodix image reply is missing its extended header");
      return FALSE;
    }

  *payload = data + GOODIX55A2_IMAGE_HEADER_SIZE;
  *payload_len = length - GOODIX55A2_IMAGE_HEADER_SIZE;
  return TRUE;
}

static void
unpack_group (const guint8 *packed,
              guint16      *pixels)
{
  pixels[0] = ((packed[0] & 0x0f) << 8) | packed[1];
  pixels[1] = (packed[3] << 4) | (packed[0] >> 4);
  pixels[2] = ((packed[5] & 0x0f) << 8) | packed[2];
  pixels[3] = (packed[4] << 4) | (packed[5] >> 4);
}

gboolean
goodix55a2_unpack_frame (const guint8 *packed,
                         gsize         packed_len,
                         guint16      *image,
                         GError      **error)
{
  if (packed_len != GOODIX55A2_PACKED_FRAME_SIZE)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid GF3206 packed frame length %" G_GSIZE_FORMAT,
                   packed_len);
      return FALSE;
    }

  for (guint wire_y = 0; wire_y < GOODIX55A2_IMAGE_WIDTH; wire_y++)
    {
      const guint8 *row = packed + wire_y * GOODIX55A2_WIRE_ROW_BYTES;
      guint active_x = 0;

      for (guint offset = 0; offset < 78; offset += 6)
        {
          guint16 pixels[4];

          unpack_group (row + offset, pixels);
          for (guint i = 0; i < G_N_ELEMENTS (pixels); i++)
            image[(active_x + i) * GOODIX55A2_IMAGE_WIDTH + wire_y] = pixels[i];
          active_x += G_N_ELEMENTS (pixels);
        }

      image[52 * GOODIX55A2_IMAGE_WIDTH + wire_y] =
        ((row[78] & 0x0f) << 8) | row[79];
      image[53 * GOODIX55A2_IMAGE_WIDTH + wire_y] =
        (row[81] << 4) | (row[78] >> 4);
    }

  return TRUE;
}

static gint
compare_u16 (gconstpointer a,
             gconstpointer b)
{
  guint16 lhs = *(const guint16 *) a;
  guint16 rhs = *(const guint16 *) b;

  return (lhs > rhs) - (lhs < rhs);
}

static gint
compare_double (gconstpointer a,
                gconstpointer b)
{
  gdouble lhs = *(const gdouble *) a;
  gdouble rhs = *(const gdouble *) b;

  return (lhs > rhs) - (lhs < rhs);
}

gboolean
goodix55a2_build_calibration (const guint16 *frames,
                              guint          frame_count,
                              guint16       *baseline,
                              GError       **error)
{
  g_autofree guint16 *samples = NULL;

  if (frame_count == 0 || !(frame_count & 1))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                           "GF3206 calibration requires an odd number of frames");
      return FALSE;
    }

  samples = g_new (guint16, frame_count);
  for (guint pixel = 0; pixel < GOODIX55A2_IMAGE_PIXELS; pixel++)
    {
      for (guint frame = 0; frame < frame_count; frame++)
        samples[frame] = frames[frame * GOODIX55A2_IMAGE_PIXELS + pixel];

      qsort (samples, frame_count, sizeof (*samples), compare_u16);
      baseline[pixel] = samples[frame_count / 2];
    }

  return TRUE;
}

gboolean
goodix55a2_calibration_is_stable (const guint16 *frames,
                                  guint          frame_count,
                                  const guint16 *baseline,
                                  gdouble        maximum_mean_deviation,
                                  GError       **error)
{
  g_autofree gdouble *frame_deviations = g_new (gdouble, frame_count);

  for (guint frame = 0; frame < frame_count; frame++)
    {
      guint64 deviation = 0;
      guint count = 0;

      for (guint y = 1; y + 1 < GOODIX55A2_IMAGE_HEIGHT; y++)
        for (guint x = 1; x + 1 < GOODIX55A2_IMAGE_WIDTH; x++)
          {
            guint index = y * GOODIX55A2_IMAGE_WIDTH + x;
            guint16 value = frames[frame * GOODIX55A2_IMAGE_PIXELS + index];

            deviation += value > baseline[index] ?
                         value - baseline[index] : baseline[index] - value;
            count++;
          }

      frame_deviations[frame] = (gdouble) deviation / count;
    }

  qsort (frame_deviations, frame_count, sizeof (*frame_deviations),
         compare_double);
  if (frame_deviations[frame_count / 2] > maximum_mean_deviation)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR,
                           FP_DEVICE_ERROR_DATA_INVALID,
                           "GF3206 calibration frames are not stable");
      return FALSE;
    }

  return TRUE;
}

void
goodix55a2_flat_field (const guint16 *raw,
                       const guint16 *baseline,
                       const guint16 *kr_q13,
                       guint16       *corrected)
{
  for (guint i = 0; i < GOODIX55A2_IMAGE_PIXELS; i++)
    {
      guint denominator = kr_q13 && kr_q13[i] ? kr_q13[i] : GOODIX55A2_Q13_ONE;
      guint signal = baseline[i] > raw[i] ? baseline[i] - raw[i] : 0;
      guint64 value = (guint64) signal * GOODIX55A2_Q13_ONE + denominator / 2;

      corrected[i] = MIN (value / denominator, 4095);
    }
}

static gdouble
percentile_from_histogram (const guint *histogram,
                           guint        count,
                           gdouble      percentile)
{
  gdouble rank = (count - 1) * percentile;
  guint lower_rank = floor (rank);
  guint upper_rank = ceil (rank);
  guint seen = 0;
  guint lower = 0;
  guint upper = 0;

  for (guint value = 0; value <= 4095; value++)
    {
      if (seen <= lower_rank && lower_rank < seen + histogram[value])
        lower = value;
      if (seen <= upper_rank && upper_rank < seen + histogram[value])
        {
          upper = value;
          break;
        }
      seen += histogram[value];
    }

  return lower + (rank - lower_rank) * (upper - lower);
}

void
goodix55a2_normalize (const guint16 *corrected,
                      guint8        *image)
{
  guint histogram[4096] = { 0 };
  guint nonzero = 0;
  guint interior = 0;
  gdouble low;
  gdouble high;

  for (guint y = 1; y + 1 < GOODIX55A2_IMAGE_HEIGHT; y++)
    for (guint x = 1; x + 1 < GOODIX55A2_IMAGE_WIDTH; x++)
      {
        guint16 value = MIN (corrected[y * GOODIX55A2_IMAGE_WIDTH + x], 4095);

        interior++;
        if (value)
          {
            histogram[value]++;
            nonzero++;
          }
      }

  if (!nonzero)
    {
      memset (histogram, 0, sizeof (histogram));
      histogram[0] = interior;
      nonzero = interior;
    }

  low = percentile_from_histogram (histogram, nonzero, 0.01);
  high = percentile_from_histogram (histogram, nonzero, 0.99);
  if (high <= low)
    {
      memset (image, 0, GOODIX55A2_IMAGE_PIXELS);
      return;
    }

  for (guint i = 0; i < GOODIX55A2_IMAGE_PIXELS; i++)
    {
      gdouble scaled = (corrected[i] - low) * 255.0 / (high - low);

      image[i] = CLAMP ((gint) nearbyint (scaled), 0, 255);
    }
}

void
goodix55a2_finger_metrics (const guint16 *corrected,
                           gdouble       *mean,
                           gdouble       *active_fraction)
{
  guint64 sum = 0;
  guint active = 0;
  guint count = 0;

  for (guint y = 1; y + 1 < GOODIX55A2_IMAGE_HEIGHT; y++)
    for (guint x = 1; x + 1 < GOODIX55A2_IMAGE_WIDTH; x++)
      {
        guint16 value = corrected[y * GOODIX55A2_IMAGE_WIDTH + x];

        sum += value;
        active += value > 24;
        count++;
      }

  *mean = (gdouble) sum / count;
  *active_fraction = (gdouble) active / count;
}

static unsigned char
swipe_get_pixel (struct fpi_frame_asmbl_ctx *ctx,
                 struct fpi_frame           *frame,
                 unsigned int                x,
                 unsigned int                y)
{
  return frame->data[y * ctx->frame_width + x];
}

FpImage *
goodix55a2_assemble_swipe (GSList *frames)
{
  struct fpi_frame_asmbl_ctx context = {
    .frame_width = GOODIX55A2_IMAGE_WIDTH,
    .frame_height = GOODIX55A2_IMAGE_HEIGHT,
    .image_width = GOODIX55A2_ASSEMBLED_WIDTH,
    .get_pixel = swipe_get_pixel,
  };

  g_return_val_if_fail (frames != NULL, NULL);

  fpi_do_movement_estimation (&context, frames);
  return fpi_assemble_frames (&context, frames);
}
