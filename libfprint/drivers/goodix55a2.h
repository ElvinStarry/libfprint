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

#pragma once

#include <glib.h>

#include "fp-image.h"

#define GOODIX55A2_IMAGE_WIDTH       176
#define GOODIX55A2_IMAGE_HEIGHT      54
#define GOODIX55A2_IMAGE_PIXELS      (GOODIX55A2_IMAGE_WIDTH * GOODIX55A2_IMAGE_HEIGHT)
#define GOODIX55A2_WIRE_ROW_BYTES    84
#define GOODIX55A2_PACKED_FRAME_SIZE (GOODIX55A2_IMAGE_WIDTH * GOODIX55A2_WIRE_ROW_BYTES)
#define GOODIX55A2_FRAME_TRAILER_SIZE 4
#define GOODIX55A2_PLAINTEXT_SIZE    (GOODIX55A2_PACKED_FRAME_SIZE + GOODIX55A2_FRAME_TRAILER_SIZE)
#define GOODIX55A2_Q13_ONE           (1 << 13)
#define GOODIX55A2_CALIBRATION_FRAMES 17
#define GOODIX55A2_CALIBRATION_VALIDATE_FRAMES 3
#define GOODIX55A2_ASSEMBLED_WIDTH   (GOODIX55A2_IMAGE_WIDTH + GOODIX55A2_IMAGE_WIDTH / 2)

gboolean goodix55a2_select_bulk_endpoints (const guint8 *addresses,
                                            gsize         address_count,
                                            guint8       *bulk_in,
                                            guint8       *bulk_out,
                                            GError      **error);

GByteArray *goodix55a2_build_command (guint8        command,
                                      const guint8 *payload,
                                      gsize         payload_len);
GByteArray *goodix55a2_build_tls (const guint8 *payload,
                                  gsize         payload_len);

gboolean goodix55a2_validate_container (const guint8 *data,
                                        gsize         length,
                                        guint8        expected_type,
                                        GError      **error);
gboolean goodix55a2_parse_command_reply (const guint8  *data,
                                         gsize          length,
                                         guint8         expected_command,
                                         const guint8 **payload,
                                         gsize         *payload_len,
                                         GError       **error);
gboolean goodix55a2_parse_tls_reply (const guint8  *data,
                                     gsize          length,
                                     const guint8 **payload,
                                     gsize         *payload_len,
                                     GError       **error);
gboolean goodix55a2_parse_image_reply (const guint8  *data,
                                       gsize          length,
                                       const guint8 **payload,
                                       gsize         *payload_len,
                                       GError       **error);

gboolean goodix55a2_unpack_frame (const guint8 *packed,
                                  gsize         packed_len,
                                  guint16      *image,
                                  GError      **error);
gboolean goodix55a2_build_calibration (const guint16 *frames,
                                       guint          frame_count,
                                       guint16       *baseline,
                                       GError       **error);
gboolean goodix55a2_calibration_is_stable (const guint16 *frames,
                                           guint          frame_count,
                                           const guint16 *baseline,
                                           gdouble        maximum_mean_deviation,
                                           GError       **error);
void goodix55a2_flat_field (const guint16 *raw,
                            const guint16 *baseline,
                            const guint16 *kr_q13,
                            guint16       *corrected);
void goodix55a2_normalize (const guint16 *corrected,
                           guint8        *image);
void goodix55a2_finger_metrics (const guint16 *corrected,
                                gdouble       *mean,
                                gdouble       *active_fraction);
FpImage *goodix55a2_assemble_swipe (GSList *frames);
