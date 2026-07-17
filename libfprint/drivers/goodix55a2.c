/*
 * Goodix GF3206 (27c6:55a2) driver for libfprint
 *
 * Copyright (C) 2026 Elvin Starry
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define FP_COMPONENT "goodix55a2"

#include "drivers_api.h"
#include "goodix55a2.h"

#include "fpi-assembling.h"
#include "fpi-byte-utils.h"
#include "fpi-log.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <string.h>

#define GOODIX55A2_MAX_TRANSFER 32768
#define GOODIX55A2_USB_TIMEOUT 10000
#define GOODIX55A2_CAPTURE_INTERVAL_MS 56
#define GOODIX55A2_CALIBRATION_MAX_DEVIATION 24.0
#define GOODIX55A2_PPMM (500.0 / 25.4)

#define GOODIX55A2_FINGER_ON_MEAN 18.0
#define GOODIX55A2_FINGER_ON_FRACTION 0.20
#define GOODIX55A2_FINGER_OFF_MEAN 10.0
#define GOODIX55A2_FINGER_OFF_FRACTION 0.12
#define GOODIX55A2_FINGER_ON_FRAMES 2
#define GOODIX55A2_FINGER_OFF_FRAMES 3
#define GOODIX55A2_MIN_SWIPE_FRAMES 7
#define GOODIX55A2_MAX_SWIPE_FRAMES 30
#define GOODIX55A2_MIN_SWIPE_HEIGHT 176

typedef struct
{
  guint8        command;
  const guint8 *payload;
  gsize         payload_len;
  guint         reply_count;
} Goodix55a2Command;

typedef struct
{
  GByteArray *packet;
  gsize       write_offset;
  guint       reply_count;
  guint       replies_received;
} Goodix55a2Exchange;

struct _FpiDeviceGoodix55a2
{
  FpImageDevice parent;

  gboolean       claimed;
  guint8         interface_number;
  guint8         bulk_in;
  guint8         bulk_out;
  gboolean       deactivating;
  gboolean       scan_delayed;
  FpiImageDeviceState state;
  FpiSsm        *scan_ssm;
  GCancellable  *io_cancellable;

  GByteArray    *rx_buffer;
  GPtrArray     *last_replies;

  SSL_CTX       *ssl_ctx;
  SSL           *ssl;
  BIO           *rbio;
  BIO           *wbio;
  gboolean       tls_ready;

  guint          init_index;
  guint          calibration_index;
  guint          calibration_target;
  guint16       *calibration_frames;
  gboolean       calibration_cached;
  gboolean       calibration_valid;
  guint16       *baseline;
  guint16       *kr_q13;
  guint16       *raw;
  guint16       *corrected;
  guint8         trailer[GOODIX55A2_FRAME_TRAILER_SIZE];

  gint64         last_capture_start;
  guint          finger_on_count;
  guint          finger_off_count;
  GSList        *swipe_frames;
  guint          swipe_frame_count;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix55a2, fpi_device_goodix55a2,
                      FPI, DEVICE_GOODIX55A2, FpImageDevice)
G_DEFINE_TYPE (FpiDeviceGoodix55a2, fpi_device_goodix55a2,
               FP_TYPE_IMAGE_DEVICE)

static const guint8 expected_firmware[] = "GF3206_RTSEC_APP_10056";
static const guint8 tls_psk[32] = { 0 };
static const guint8 expected_pmk_hash[] = {
  0x81, 0xb8, 0xff, 0x49, 0x06, 0x12, 0x02, 0x2a,
  0x12, 0x1a, 0x94, 0x49, 0xee, 0x3a, 0xad, 0x27,
  0x92, 0xf3, 0x2b, 0x9f, 0x31, 0x41, 0x18, 0x2c,
  0xd0, 0x10, 0x19, 0x94, 0x5e, 0xe5, 0x03, 0x61,
};

static const guint8 nop_payload[] = { 0x00, 0x00, 0x00, 0x00 };
static const guint8 firmware_payload[] = { 0x00, 0x00 };
static const guint8 pmk_query_payload[] = {
  0x07, 0x00, 0x02, 0xbb, 0x00, 0x00, 0x00, 0x00,
};
static const guint8 psk_id_payload[] = {
  0x02, 0x00, 0x01, 0xbb, 0x0e, 0x00, 0x00, 0x00,
  0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42,
  0x43, 0x43, 0x43, 0x43, 0x44, 0x44,
};
static const guint8 psk_payload[] = {
  0x03, 0x00, 0x01, 0xbb, 0x60, 0x00, 0x00, 0x00,
  0xec, 0x35, 0xae, 0x3a, 0xbb, 0x45, 0xed, 0x3f,
  0x12, 0xc4, 0x75, 0x1f, 0x1e, 0x5c, 0x2c, 0xc0,
  0x5b, 0x3c, 0x54, 0x52, 0xe9, 0x10, 0x4d, 0x9f,
  0x2a, 0x31, 0x18, 0x64, 0x4f, 0x37, 0xa0, 0x4b,
  0x6f, 0xd6, 0x6b, 0x1d, 0x97, 0xcf, 0x80, 0xf1,
  0x34, 0x5f, 0x76, 0xc8, 0x4f, 0x03, 0xff, 0x30,
  0xbb, 0x51, 0xbf, 0x30, 0x8f, 0x2a, 0x98, 0x75,
  0xc4, 0x1e, 0x65, 0x92, 0xcd, 0x2a, 0x2f, 0x9e,
  0x60, 0x80, 0x9b, 0x17, 0xb5, 0x31, 0x60, 0x37,
  0xb6, 0x9b, 0xb2, 0xfa, 0x5d, 0x4c, 0x8a, 0xc3,
  0x1e, 0xdb, 0x33, 0x94, 0x04, 0x6e, 0xc0, 0x6b,
  0xbd, 0xac, 0xc5, 0x7d, 0xa6, 0xa7, 0x56, 0xc5,
};
static const guint8 chip_config[] = {
  0x30, 0x11, 0x60, 0x71, 0x2c, 0x9d, 0x2c, 0xc9, 0x1c, 0xe5, 0x18, 0xfd,
  0x00, 0xfd, 0x00, 0xfd, 0x03, 0xba, 0x00, 0x00, 0x80, 0xca, 0x00, 0x06,
  0x00, 0x84, 0x00, 0xbe, 0xb2, 0x86, 0x00, 0xc5, 0xb9, 0x88, 0x00, 0xb5,
  0xad, 0x8a, 0x00, 0x9d, 0x95, 0x8c, 0x00, 0x00, 0xbe, 0x8e, 0x00, 0x00,
  0xc5, 0x90, 0x00, 0x00, 0xb5, 0x92, 0x00, 0x00, 0x9d, 0x94, 0x00, 0x00,
  0xaf, 0x96, 0x00, 0x00, 0xbf, 0x98, 0x00, 0x00, 0xb6, 0x9a, 0x00, 0x00,
  0xa7, 0xd2, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00,
  0x00, 0xd8, 0x00, 0x00, 0x00, 0x12, 0x00, 0x03, 0x04, 0xd0, 0x00, 0x00,
  0x00, 0x70, 0x00, 0x00, 0x00, 0x72, 0x00, 0x78, 0x56, 0x74, 0x00, 0x34,
  0x12, 0x20, 0x00, 0x10, 0x40, 0x2a, 0x01, 0x02, 0x00, 0x22, 0x00, 0x01,
  0x20, 0x24, 0x00, 0x32, 0x00, 0x80, 0x00, 0x01, 0x04, 0x5c, 0x00, 0x00,
  0x01, 0x56, 0x00, 0x30, 0x48, 0x58, 0x00, 0x02, 0x00, 0x32, 0x00, 0x08,
  0x02, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00, 0x38, 0x82, 0x00, 0x80,
  0x15, 0x2a, 0x01, 0x82, 0x03, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x14,
  0x00, 0x80, 0x00, 0x01, 0x04, 0x5c, 0x00, 0x00, 0x01, 0x56, 0x00, 0x0c,
  0x24, 0x58, 0x00, 0x05, 0x00, 0x32, 0x00, 0x08, 0x02, 0x66, 0x00, 0x00,
  0x02, 0x7c, 0x00, 0x00, 0x38, 0x82, 0x00, 0x80, 0x16, 0x2a, 0x01, 0x08,
  0x00, 0x5c, 0x00, 0x80, 0x00, 0x54, 0x00, 0x00, 0x01, 0x62, 0x00, 0x38,
  0x04, 0x64, 0x00, 0x10, 0x00, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x01,
  0x38, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0x00, 0x01, 0x52, 0x00, 0x08,
  0x00, 0x54, 0x00, 0x00, 0x01, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x01,
  0x38, 0x00, 0xe8, 0x58,
};
static const guint8 fdt_mode[] = {
  0x0d, 0x01, 0x80, 0xa0, 0x80, 0x93, 0x80, 0x9b, 0x80, 0x94, 0x80,
  0x90, 0x80, 0x8f, 0x80, 0x94, 0x80, 0x8b, 0x80, 0x8a, 0x80, 0x83,
};

static const guint8 reset_payload[] = { 0x05, 0x14 };
static const guint8 read_reg_payload[] = { 0x00, 0x00, 0x00, 0x04, 0x00 };
static const guint8 zero_payload[] = { 0x00, 0x00 };
static const guint8 driver_state_payload[] = { 0x01, 0x00 };
static const guint8 capture_payload[] = { 0x01, 0x00 };

static const Goodix55a2Command init_commands[] = {
  { 0xa2, reset_payload, sizeof (reset_payload), 2 },
  { 0x82, read_reg_payload, sizeof (read_reg_payload), 2 },
  { 0x00, nop_payload, sizeof (nop_payload), 1 },
  { 0xa6, zero_payload, sizeof (zero_payload), 2 },
  { 0xd6, zero_payload, sizeof (zero_payload), 2 },
  { 0x90, chip_config, sizeof (chip_config), 2 },
  { 0xc4, driver_state_payload, sizeof (driver_state_payload), 1 },
  { 0xd2, zero_payload, sizeof (zero_payload), 2 },
  { 0x36, fdt_mode, sizeof (fdt_mode), 2 },
};

static GError *
openssl_error (const char *message)
{
  unsigned long code = ERR_get_error ();
  g_autofree char *detail = NULL;

  if (code)
    detail = g_strdup (ERR_error_string (code, NULL));
  else
    detail = g_strdup ("unknown OpenSSL error");

  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                   "%s: %s", message, detail);
}

static void
exchange_free (Goodix55a2Exchange *exchange)
{
  g_clear_pointer (&exchange->packet, g_byte_array_unref);
  g_free (exchange);
}

static void exchange_read_more (FpiSsm *ssm);

static GCancellable *
transfer_cancellable (FpiDeviceGoodix55a2 *self)
{
  if (self->io_cancellable)
    return self->io_cancellable;

  return fpi_device_get_cancellable (FP_DEVICE (self));
}

static void
exchange_write_cb (FpiUsbTransfer *transfer,
                   FpDevice       *device,
                   gpointer        user_data,
                   GError         *error)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);
  Goodix55a2Exchange *exchange = fpi_ssm_get_data (transfer->ssm);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if (transfer->actual_length != transfer->length)
    {
      fpi_ssm_mark_failed (
        transfer->ssm,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                  "Short GF3206 USB write (%" G_GSSIZE_FORMAT
                                  " of %" G_GSSIZE_FORMAT " bytes)",
                                  transfer->actual_length, transfer->length));
      return;
    }

  exchange->write_offset += transfer->actual_length;
  if (exchange->write_offset < exchange->packet->len)
    {
      FpiUsbTransfer *next = fpi_usb_transfer_new (device);
      gsize length = MIN ((gsize) 64,
                          exchange->packet->len - exchange->write_offset);

      fpi_usb_transfer_fill_bulk_full (
        next, self->bulk_out,
        g_memdup2 (exchange->packet->data + exchange->write_offset, length),
        length, g_free);
      next->ssm = transfer->ssm;
      next->short_is_error = TRUE;
      fpi_usb_transfer_submit (next, GOODIX55A2_USB_TIMEOUT,
                               transfer_cancellable (
                                 FPI_DEVICE_GOODIX55A2 (device)),
                               exchange_write_cb, NULL);
      return;
    }

  fpi_ssm_next_state (transfer->ssm);
}

static gboolean
exchange_consume_reply (FpiSsm *ssm)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (fpi_ssm_get_device (ssm));
  Goodix55a2Exchange *exchange = fpi_ssm_get_data (ssm);
  g_autoptr(GError) error = NULL;
  gsize packet_len;
  guint8 type;

  if (self->rx_buffer->len < 4)
    return FALSE;

  type = self->rx_buffer->data[0];
  if (type != 0xa0 && type != 0xb0 && type != 0xb2)
    {
      fpi_ssm_mark_failed (ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Unknown Goodix reply type 0x%02x",
                                                     type));
      return TRUE;
    }

  packet_len = FP_READ_UINT16_LE (self->rx_buffer->data + 1) + 4;
  if (packet_len > GOODIX55A2_MAX_TRANSFER)
    {
      fpi_ssm_mark_failed (ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Oversized Goodix reply (%" G_GSIZE_FORMAT " bytes)",
                                                     packet_len));
      return TRUE;
    }
  if (self->rx_buffer->len < packet_len)
    return FALSE;

  if (!goodix55a2_validate_container (self->rx_buffer->data,
                                      packet_len, type, &error))
    {
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return TRUE;
    }

  g_ptr_array_add (self->last_replies,
                   g_byte_array_new_take (g_memdup2 (self->rx_buffer->data,
                                                     packet_len),
                                          packet_len));
  g_byte_array_remove_range (self->rx_buffer, 0, packet_len);
  exchange->replies_received++;

  if (exchange->replies_received == exchange->reply_count)
    {
      if (self->rx_buffer->len)
        fpi_ssm_mark_failed (
          ssm,
          fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                    "Unexpected data after GF3206 reply"));
      else
        fpi_ssm_mark_completed (ssm);
    }
  else
    exchange_read_more (ssm);

  return TRUE;
}

static void
exchange_read_cb (FpiUsbTransfer *transfer,
                  FpDevice       *device,
                  gpointer        user_data,
                  GError         *error)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if (transfer->actual_length <= 0)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Empty Goodix USB reply"));
      return;
    }

  g_byte_array_append (self->rx_buffer, transfer->buffer,
                       transfer->actual_length);
  if (!exchange_consume_reply (transfer->ssm))
    exchange_read_more (transfer->ssm);
}

static void
exchange_read_more (FpiSsm *ssm)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (fpi_ssm_get_device (ssm));
  FpiUsbTransfer *transfer;

  if (exchange_consume_reply (ssm))
    return;

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, self->bulk_in,
                              GOODIX55A2_MAX_TRANSFER);
  transfer->ssm = ssm;
  transfer->short_is_error = FALSE;
  fpi_usb_transfer_submit (transfer, GOODIX55A2_USB_TIMEOUT,
                           transfer_cancellable (self),
                           exchange_read_cb, NULL);
}

enum exchange_states
{
  EXCHANGE_WRITE,
  EXCHANGE_READ,
  EXCHANGE_NUM_STATES,
};

static void
exchange_run_state (FpiSsm *ssm,
                    FpDevice *device)
{
  Goodix55a2Exchange *exchange = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case EXCHANGE_WRITE:
      {
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (device);
        gsize length = MIN ((gsize) 64, exchange->packet->len);

        fpi_usb_transfer_fill_bulk_full (
          transfer, FPI_DEVICE_GOODIX55A2 (device)->bulk_out,
          g_memdup2 (exchange->packet->data, length), length, g_free);
        transfer->ssm = ssm;
        transfer->short_is_error = TRUE;
        fpi_usb_transfer_submit (transfer, GOODIX55A2_USB_TIMEOUT,
                                 transfer_cancellable (
                                   FPI_DEVICE_GOODIX55A2 (device)),
                                 exchange_write_cb, NULL);
        break;
      }

    case EXCHANGE_READ:
      if (exchange->reply_count == 0)
        fpi_ssm_mark_completed (ssm);
      else
        exchange_read_more (ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
start_exchange (FpiSsm    *parent,
                GByteArray *packet,
                guint       reply_count)
{
  FpiDeviceGoodix55a2 *self =
    FPI_DEVICE_GOODIX55A2 (fpi_ssm_get_device (parent));
  Goodix55a2Exchange *exchange = g_new0 (Goodix55a2Exchange, 1);
  FpiSsm *child;

  exchange->packet = g_byte_array_ref (packet);
  exchange->reply_count = reply_count;
  g_clear_pointer (&self->last_replies, g_ptr_array_unref);
  self->last_replies = g_ptr_array_new_with_free_func (
    (GDestroyNotify) g_byte_array_unref);

  child = fpi_ssm_new (FP_DEVICE (self), exchange_run_state,
                       EXCHANGE_NUM_STATES);
  fpi_ssm_set_data (child, exchange, (GDestroyNotify) exchange_free);
  fpi_ssm_start_subsm (parent, child);
}

static void
start_command (FpiSsm       *parent,
               guint8        command,
               const guint8 *payload,
               gsize         payload_len,
               guint         reply_count)
{
  g_autoptr(GByteArray) packet =
    goodix55a2_build_command (command, payload, payload_len);

  start_exchange (parent, packet, reply_count);
}

static gboolean
check_command_replies (FpiDeviceGoodix55a2 *self,
                       guint8                command,
                       guint                 reply_count,
                       const guint8        **response,
                       gsize                *response_len,
                       GError              **error)
{
  const guint8 *payload;
  gsize payload_len;
  GByteArray *reply;

  if (!self->last_replies || self->last_replies->len != reply_count)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "Unexpected number of Goodix command replies");
      return FALSE;
    }

  reply = g_ptr_array_index (self->last_replies, 0);
  if (!goodix55a2_parse_command_ack (reply->data, reply->len,
                                     command, error))
    return FALSE;

  if (reply_count == 2)
    {
      reply = g_ptr_array_index (self->last_replies, 1);
      if (!goodix55a2_parse_command_reply (reply->data, reply->len, command,
                                           &payload, &payload_len, error))
        return FALSE;
      if (response)
        *response = payload;
      if (response_len)
        *response_len = payload_len;
    }

  return TRUE;
}

static unsigned int
psk_server_cb (SSL                *ssl,
               const char         *identity,
               unsigned char      *psk,
               unsigned int        max_psk_len)
{
  if (g_strcmp0 (identity, "Client_identity") != 0 ||
      max_psk_len < sizeof (tls_psk))
    return 0;

  memcpy (psk, tls_psk, sizeof (tls_psk));
  return sizeof (tls_psk);
}

static void
tls_clear (FpiDeviceGoodix55a2 *self)
{
  if (self->ssl)
    SSL_free (self->ssl);
  if (self->ssl_ctx)
    SSL_CTX_free (self->ssl_ctx);

  self->ssl = NULL;
  self->ssl_ctx = NULL;
  self->rbio = NULL;
  self->wbio = NULL;
  self->tls_ready = FALSE;
}

static gboolean
tls_prepare (FpiDeviceGoodix55a2 *self,
             GError             **error)
{
  BIO *rbio;
  BIO *wbio;

  tls_clear (self);
  ERR_clear_error ();

  self->ssl_ctx = SSL_CTX_new (TLS_server_method ());
  if (!self->ssl_ctx)
    goto failure;
  if (!SSL_CTX_set_min_proto_version (self->ssl_ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version (self->ssl_ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_cipher_list (self->ssl_ctx,
                                "PSK-AES128-CBC-SHA256"))
    goto failure;
  SSL_CTX_set_psk_server_callback (self->ssl_ctx, psk_server_cb);

  self->ssl = SSL_new (self->ssl_ctx);
  rbio = BIO_new (BIO_s_mem ());
  wbio = BIO_new (BIO_s_mem ());
  if (!self->ssl || !rbio || !wbio)
    {
      BIO_free (rbio);
      BIO_free (wbio);
      goto failure;
    }

  SSL_set_bio (self->ssl, rbio, wbio);
  self->rbio = SSL_get_rbio (self->ssl);
  self->wbio = SSL_get_wbio (self->ssl);
  SSL_set_accept_state (self->ssl);
  return TRUE;

failure:
  g_propagate_error (error, openssl_error ("Failed to initialize GF3206 TLS"));
  tls_clear (self);
  return FALSE;
}

static gboolean
tls_feed (FpiDeviceGoodix55a2 *self,
          const guint8        *data,
          gsize                length,
          GError             **error)
{
  if (BIO_write (self->rbio, data, length) != (gint) length)
    {
      g_propagate_error (error, openssl_error ("Failed to feed GF3206 TLS"));
      return FALSE;
    }

  return TRUE;
}

static gboolean
tls_handshake_step (FpiDeviceGoodix55a2 *self,
                    GError             **error)
{
  int result = SSL_do_handshake (self->ssl);
  int ssl_error;

  if (result == 1)
    {
      self->tls_ready = TRUE;
      return TRUE;
    }

  ssl_error = SSL_get_error (self->ssl, result);
  if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
    return TRUE;

  g_propagate_error (error, openssl_error ("GF3206 TLS handshake failed"));
  return FALSE;
}

static GByteArray *
tls_drain (FpiDeviceGoodix55a2 *self,
           GError             **error)
{
  GByteArray *result = g_byte_array_new ();
  guint8 buffer[1024];

  while (BIO_ctrl_pending (self->wbio))
    {
      gint length = BIO_read (self->wbio, buffer, sizeof (buffer));

      if (length <= 0)
        {
          g_byte_array_unref (result);
          g_propagate_error (error,
                             openssl_error ("Failed to drain GF3206 TLS"));
          return NULL;
        }
      g_byte_array_append (result, buffer, length);
    }

  return result;
}

enum capture_states
{
  CAPTURE_SEND,
  CAPTURE_DECRYPT,
  CAPTURE_NUM_STATES,
};

static void
capture_run_state (FpiSsm *ssm,
                   FpDevice *device)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);
  g_autoptr(GError) error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAPTURE_SEND:
      self->last_capture_start = g_get_monotonic_time ();
      start_command (ssm, 0x20, capture_payload, sizeof (capture_payload), 2);
      break;

    case CAPTURE_DECRYPT:
      {
        const guint8 *tls_payload;
        gsize tls_len;
        GByteArray *reply;
        g_autoptr(GByteArray) plaintext = g_byte_array_sized_new (
          GOODIX55A2_PLAINTEXT_SIZE);

        if (!self->last_replies || self->last_replies->len != 2)
          goto invalid_capture;

        reply = g_ptr_array_index (self->last_replies, 0);
        if (!goodix55a2_parse_command_ack (reply->data, reply->len,
                                           0x20, &error))
          goto capture_failure;

        reply = g_ptr_array_index (self->last_replies, 1);
        if (!goodix55a2_parse_image_reply (reply->data, reply->len,
                                           &tls_payload, &tls_len, &error) ||
            !tls_feed (self, tls_payload, tls_len, &error))
          goto capture_failure;

        while (plaintext->len < GOODIX55A2_PLAINTEXT_SIZE)
          {
            guint8 buffer[GOODIX55A2_PLAINTEXT_SIZE];
            gint length = SSL_read (self->ssl, buffer,
                                    GOODIX55A2_PLAINTEXT_SIZE - plaintext->len);

            if (length > 0)
              {
                g_byte_array_append (plaintext, buffer, length);
                continue;
              }

            if (SSL_get_error (self->ssl, length) == SSL_ERROR_WANT_READ)
              {
                g_set_error_literal (&error, FP_DEVICE_ERROR,
                                     FP_DEVICE_ERROR_PROTO,
                                     "Incomplete GF3206 TLS image record");
                goto capture_failure;
              }

            g_clear_error (&error);
            error = openssl_error ("Failed to decrypt GF3206 image");
            goto capture_failure;
          }

        if (!goodix55a2_unpack_frame (plaintext->data,
                                      GOODIX55A2_PACKED_FRAME_SIZE,
                                      self->raw, &error))
          goto capture_failure;
        memcpy (self->trailer,
                plaintext->data + GOODIX55A2_PACKED_FRAME_SIZE,
                sizeof (self->trailer));
        fpi_ssm_mark_completed (ssm);
        break;

invalid_capture:
        g_set_error_literal (&error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                             "Invalid GF3206 capture reply count");
capture_failure:
        fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
start_capture (FpiSsm *parent)
{
  FpiSsm *child = fpi_ssm_new (fpi_ssm_get_device (parent),
                               capture_run_state, CAPTURE_NUM_STATES);

  fpi_ssm_start_subsm (parent, child);
}

static void
jump_to_capture_at_rate (FpiSsm *ssm,
                         gint    state)
{
  FpiDeviceGoodix55a2 *self =
    FPI_DEVICE_GOODIX55A2 (fpi_ssm_get_device (ssm));
  gint64 elapsed = g_get_monotonic_time () - self->last_capture_start;
  gint delay = MAX (0, GOODIX55A2_CAPTURE_INTERVAL_MS -
                       (gint) (elapsed / 1000));

  if (delay)
    fpi_ssm_jump_to_state_delayed (ssm, state, delay);
  else
    fpi_ssm_jump_to_state (ssm, state);
}

enum open_states
{
  OPEN_FIRMWARE_SEND,
  OPEN_FIRMWARE_CHECK,
  OPEN_INIT_SEND,
  OPEN_INIT_CHECK,
  OPEN_SESSION_NOP_SEND,
  OPEN_SESSION_NOP_CHECK,
  OPEN_SESSION_FIRMWARE_SEND,
  OPEN_SESSION_FIRMWARE_CHECK,
  OPEN_PMK_SEND,
  OPEN_PMK_CHECK,
  OPEN_PSK_ID_SEND,
  OPEN_PSK_ID_CHECK,
  OPEN_PSK_SEND,
  OPEN_PSK_CHECK,
  OPEN_TLS_PREPARE,
  OPEN_TLS_CONNECT_SEND,
  OPEN_TLS_CONNECT_PROCESS,
  OPEN_TLS_FINISH_PROCESS,
  OPEN_CALIBRATION_CAPTURE,
  OPEN_CALIBRATION_COLLECT,
  OPEN_CALIBRATION_BUILD,
  OPEN_NUM_STATES,
};

static gboolean
check_firmware (FpiDeviceGoodix55a2 *self,
                GError             **error)
{
  const guint8 *payload;
  gsize payload_len;
  g_autofree char *firmware = NULL;
  g_autofree char *firmware_valid = NULL;

  if (!check_command_replies (self, 0xa8, 2, &payload, &payload_len, error))
    return FALSE;
  if (payload_len == 0)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR,
                           FP_DEVICE_ERROR_PROTO,
                           "GF3206 firmware response is empty");
      return FALSE;
    }

  firmware = g_strndup ((const char *) payload, payload_len);
  firmware_valid = g_utf8_make_valid (firmware, -1);
  if (payload_len == sizeof (expected_firmware) &&
      memcmp (payload, expected_firmware, sizeof (expected_firmware)) == 0)
    fp_dbg ("GF3206 firmware: %s", firmware_valid);
  else
    fp_warn ("Untested GF3206 firmware '%s'; continuing as the PoC does",
             firmware_valid);

  return TRUE;
}

static void
open_run_state (FpiSsm *ssm,
                FpDevice *device)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);
  g_autoptr(GError) error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_FIRMWARE_SEND:
      start_command (ssm, 0xa8, firmware_payload, sizeof (firmware_payload), 2);
      break;

    case OPEN_FIRMWARE_CHECK:
      if (!check_firmware (self, &error))
        goto failure;
      self->init_index = 0;
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_INIT_SEND:
      {
        const Goodix55a2Command *command = &init_commands[self->init_index];

        start_command (ssm, command->command, command->payload,
                       command->payload_len, command->reply_count);
        break;
      }

    case OPEN_INIT_CHECK:
      {
        const Goodix55a2Command *command = &init_commands[self->init_index];

        if (!check_command_replies (self, command->command,
                                    command->reply_count, NULL, NULL, &error))
          goto failure;
        self->init_index++;
        if (self->init_index < G_N_ELEMENTS (init_commands))
          fpi_ssm_jump_to_state (ssm, OPEN_INIT_SEND);
        else
          fpi_ssm_next_state (ssm);
        break;
      }

    case OPEN_SESSION_NOP_SEND:
      start_command (ssm, 0x00, nop_payload, sizeof (nop_payload), 1);
      break;

    case OPEN_SESSION_NOP_CHECK:
      if (!check_command_replies (self, 0x00, 1, NULL, NULL, &error))
        goto failure;
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_SESSION_FIRMWARE_SEND:
      start_command (ssm, 0xa8, firmware_payload, sizeof (firmware_payload), 2);
      break;

    case OPEN_SESSION_FIRMWARE_CHECK:
      if (!check_firmware (self, &error))
        goto failure;
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_PMK_SEND:
      start_command (ssm, 0xe4, pmk_query_payload,
                     sizeof (pmk_query_payload), 2);
      break;

    case OPEN_PMK_CHECK:
      {
        static const guint8 prefix[] = {
          0x00, 0x07, 0x00, 0x02, 0xbb, 0x20, 0x00, 0x00, 0x00,
        };
        const guint8 *payload;
        gsize payload_len;

        if (!check_command_replies (self, 0xe4, 2,
                                    &payload, &payload_len, &error))
          goto failure;
        if (payload_len != sizeof (prefix) + sizeof (expected_pmk_hash) ||
            memcmp (payload, prefix, sizeof (prefix)) != 0)
          {
            g_set_error_literal (&error, FP_DEVICE_ERROR,
                                 FP_DEVICE_ERROR_PROTO,
                                 "Invalid GF3206 PMK query response");
            goto failure;
          }

        if (memcmp (payload + sizeof (prefix), expected_pmk_hash,
                    sizeof (expected_pmk_hash)) == 0)
          fpi_ssm_jump_to_state (ssm, OPEN_TLS_PREPARE);
        else
          {
            fp_warn ("GF3206 PMK differs; provisioning the PoC PSK");
            fpi_ssm_next_state (ssm);
          }
        break;
      }

    case OPEN_PSK_ID_SEND:
      start_command (ssm, 0xe0, psk_id_payload, sizeof (psk_id_payload), 2);
      break;

    case OPEN_PSK_ID_CHECK:
      if (!check_command_replies (self, 0xe0, 2, NULL, NULL, &error))
        goto failure;
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_PSK_SEND:
      start_command (ssm, 0xe0, psk_payload, sizeof (psk_payload), 2);
      break;

    case OPEN_PSK_CHECK:
      if (!check_command_replies (self, 0xe0, 2, NULL, NULL, &error))
        goto failure;
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_TLS_PREPARE:
      if (!tls_prepare (self, &error))
        goto failure;
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_TLS_CONNECT_SEND:
      start_command (ssm, 0xd0, zero_payload, sizeof (zero_payload), 2);
      break;

    case OPEN_TLS_CONNECT_PROCESS:
      {
        const guint8 *payload;
        gsize payload_len;
        GByteArray *reply;
        g_autoptr(GByteArray) server_flight = NULL;
        g_autoptr(GByteArray) packet = NULL;

        if (!self->last_replies || self->last_replies->len != 2)
          {
            g_set_error_literal (&error, FP_DEVICE_ERROR,
                                 FP_DEVICE_ERROR_PROTO,
                                 "Invalid GF3206 TLS connect reply count");
            goto failure;
          }
        reply = g_ptr_array_index (self->last_replies, 0);
        if (!goodix55a2_parse_command_ack (reply->data, reply->len,
                                           0xd0, &error))
          goto failure;
        reply = g_ptr_array_index (self->last_replies, 1);
        if (!goodix55a2_parse_tls_reply (reply->data, reply->len,
                                         &payload, &payload_len, &error) ||
            !tls_feed (self, payload, payload_len, &error) ||
            !tls_handshake_step (self, &error))
          goto failure;

        server_flight = tls_drain (self, &error);
        if (!server_flight || server_flight->len == 0)
          {
            if (!error)
              g_set_error_literal (&error, FP_DEVICE_ERROR,
                                   FP_DEVICE_ERROR_PROTO,
                                   "GF3206 TLS produced no server flight");
            goto failure;
          }
        packet = goodix55a2_build_tls (server_flight->data,
                                       server_flight->len);
        start_exchange (ssm, packet, 3);
        break;
      }

    case OPEN_TLS_FINISH_PROCESS:
      {
        g_autoptr(GByteArray) server_flight = NULL;
        g_autoptr(GByteArray) packet = NULL;

        if (!self->last_replies || self->last_replies->len != 3)
          {
            g_set_error_literal (&error, FP_DEVICE_ERROR,
                                 FP_DEVICE_ERROR_PROTO,
                                 "Invalid GF3206 TLS handshake reply count");
            goto failure;
          }

        for (guint i = 0; i < self->last_replies->len; i++)
          {
            GByteArray *reply = g_ptr_array_index (self->last_replies, i);
            const guint8 *payload;
            gsize payload_len;

            if (!goodix55a2_parse_tls_reply (reply->data, reply->len,
                                             &payload, &payload_len, &error) ||
                !tls_feed (self, payload, payload_len, &error) ||
                !tls_handshake_step (self, &error))
              goto failure;
          }
        if (!self->tls_ready)
          {
            g_set_error_literal (&error, FP_DEVICE_ERROR,
                                 FP_DEVICE_ERROR_PROTO,
                                 "GF3206 TLS handshake did not complete");
            goto failure;
          }

        server_flight = tls_drain (self, &error);
        if (!server_flight || server_flight->len == 0)
          {
            if (!error)
              g_set_error_literal (&error, FP_DEVICE_ERROR,
                                   FP_DEVICE_ERROR_PROTO,
                                   "GF3206 TLS produced no final flight");
            goto failure;
          }
        packet = goodix55a2_build_tls (server_flight->data,
                                       server_flight->len);
        start_exchange (ssm, packet, 0);
        break;
      }

    case OPEN_CALIBRATION_CAPTURE:
      start_capture (ssm);
      break;

    case OPEN_CALIBRATION_COLLECT:
      memcpy (self->calibration_frames +
              self->calibration_index * GOODIX55A2_IMAGE_PIXELS,
              self->raw,
              GOODIX55A2_IMAGE_PIXELS * sizeof (*self->raw));
      self->calibration_index++;
      if (self->calibration_index < self->calibration_target)
        jump_to_capture_at_rate (ssm, OPEN_CALIBRATION_CAPTURE);
      else
        fpi_ssm_next_state (ssm);
      break;

    case OPEN_CALIBRATION_BUILD:
      if (self->calibration_cached)
        {
          if (goodix55a2_calibration_is_stable (
                self->calibration_frames,
                GOODIX55A2_CALIBRATION_VALIDATE_FRAMES,
                self->baseline, GOODIX55A2_CALIBRATION_MAX_DEVIATION,
                &error))
            {
              fp_dbg ("GF3206 cached calibration validated");
              self->calibration_valid = TRUE;
              g_clear_pointer (&self->calibration_frames, g_free);
              fpi_ssm_mark_completed (ssm);
              break;
            }

          fp_dbg ("GF3206 cached calibration rejected; rebuilding");
          g_clear_error (&error);
          self->calibration_cached = FALSE;
          self->calibration_target = GOODIX55A2_CALIBRATION_FRAMES;
          self->calibration_frames = g_renew (
            guint16, self->calibration_frames,
            GOODIX55A2_CALIBRATION_FRAMES * GOODIX55A2_IMAGE_PIXELS);
          jump_to_capture_at_rate (ssm, OPEN_CALIBRATION_CAPTURE);
          break;
        }

      if (!goodix55a2_build_calibration (self->calibration_frames,
                                         GOODIX55A2_CALIBRATION_FRAMES,
                                         self->baseline, &error))
        goto failure;
      if (!goodix55a2_calibration_is_stable (
            self->calibration_frames, GOODIX55A2_CALIBRATION_FRAMES,
            self->baseline, GOODIX55A2_CALIBRATION_MAX_DEVIATION, &error))
        goto failure;
      for (guint i = 0; i < GOODIX55A2_IMAGE_PIXELS; i++)
        self->kr_q13[i] = GOODIX55A2_Q13_ONE;
      self->calibration_cached = TRUE;
      self->calibration_valid = TRUE;
      g_clear_pointer (&self->calibration_frames, g_free);
      fpi_ssm_mark_completed (ssm);
      break;

    default:
      g_assert_not_reached ();
    }
  return;

failure:
  fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
}

static void
release_interface (FpiDeviceGoodix55a2 *self,
                   GError             **error)
{
  if (!self->claimed)
    return;

  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)),
                                  self->interface_number, 0, error);
  self->claimed = FALSE;
}

static void
open_complete (FpiSsm *ssm,
               FpDevice *device,
               GError *error)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);

  g_clear_pointer (&self->calibration_frames, g_free);
  if (error)
    {
      tls_clear (self);
      release_interface (self, NULL);
    }

  fpi_image_device_open_complete (FP_IMAGE_DEVICE (self), error);
}

static gboolean
claim_and_validate_interface (FpiDeviceGoodix55a2 *self,
                              GError             **error)
{
  GUsbDevice *usb = fpi_device_get_usb_device (FP_DEVICE (self));
  g_autoptr(GPtrArray) interfaces = NULL;
  guint8 interface_number = 0;
  guint8 bulk_in = 0;
  guint8 bulk_out = 0;
  gboolean found = FALSE;

  if (!g_usb_device_set_configuration (usb, 1, error))
    return FALSE;

  interfaces = g_usb_device_get_interfaces (usb, error);
  if (!interfaces)
    return FALSE;

  for (guint i = 0; i < interfaces->len; i++)
    {
      GUsbInterface *interface = g_ptr_array_index (interfaces, i);

      g_autoptr(GPtrArray) endpoints = NULL;
      g_autofree guint8 *addresses = NULL;

      if (g_usb_interface_get_alternate (interface) != 0 ||
          g_usb_interface_get_class (interface) !=
            G_USB_DEVICE_CLASS_VENDOR_SPECIFIC)
        continue;

      endpoints = g_usb_interface_get_endpoints (interface);
      addresses = g_new (guint8, endpoints->len);

      /* GUsb exposes bDescriptorType through get_kind(), not bmAttributes.
       * The GF3206 vendor interface contains only its bulk endpoint pair. */
      for (guint endpoint_index = 0;
           endpoint_index < endpoints->len;
           endpoint_index++)
        {
          GUsbEndpoint *endpoint = g_ptr_array_index (endpoints,
                                                      endpoint_index);

          addresses[endpoint_index] = g_usb_endpoint_get_address (endpoint);
          fp_dbg ("GF3206 endpoint 0x%02x, max packet size %u",
                  addresses[endpoint_index],
                  g_usb_endpoint_get_maximum_packet_size (endpoint));
        }

      if (!goodix55a2_select_bulk_endpoints (addresses, endpoints->len,
                                             &bulk_in, &bulk_out, NULL))
        continue;

      interface_number = g_usb_interface_get_number (interface);
      found = TRUE;
      break;
    }
  if (!found)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED,
                           "GF3206 USB interface or bulk endpoints are missing");
      return FALSE;
    }

  if (!g_usb_device_claim_interface (usb, interface_number, 0, error))
    return FALSE;
  self->interface_number = interface_number;
  self->bulk_in = bulk_in;
  self->bulk_out = bulk_out;
  self->claimed = TRUE;
  fp_dbg ("GF3206 using interface %u, bulk OUT 0x%02x, bulk IN 0x%02x",
          self->interface_number, self->bulk_out, self->bulk_in);
  return TRUE;
}

static void
dev_open (FpImageDevice *device)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);
  g_autoptr(GError) error = NULL;
  FpiSsm *ssm;

  if (!claim_and_validate_interface (self, &error))
    {
      fpi_image_device_open_complete (device, g_steal_pointer (&error));
      return;
    }

  g_clear_object (&self->io_cancellable);
  g_byte_array_set_size (self->rx_buffer, 0);
  self->calibration_valid = FALSE;
  self->calibration_index = 0;
  self->calibration_target = self->calibration_cached ?
                             GOODIX55A2_CALIBRATION_VALIDATE_FRAMES :
                             GOODIX55A2_CALIBRATION_FRAMES;
  g_clear_pointer (&self->calibration_frames, g_free);
  self->calibration_frames = g_new (guint16,
                                    self->calibration_target *
                                    GOODIX55A2_IMAGE_PIXELS);

  ssm = fpi_ssm_new (FP_DEVICE (self), open_run_state, OPEN_NUM_STATES);
  fpi_ssm_start (ssm, open_complete);
}

static void
dev_close (FpImageDevice *device)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);
  GError *error = NULL;

  tls_clear (self);
  g_clear_object (&self->io_cancellable);
  g_byte_array_set_size (self->rx_buffer, 0);
  g_clear_pointer (&self->last_replies, g_ptr_array_unref);
  g_slist_free_full (self->swipe_frames, g_free);
  self->swipe_frames = NULL;
  self->swipe_frame_count = 0;
  self->calibration_valid = FALSE;
  release_interface (self, &error);
  fpi_image_device_close_complete (device, error);
}

static void
clear_swipe_frames (FpiDeviceGoodix55a2 *self)
{
  g_slist_free_full (self->swipe_frames, g_free);
  self->swipe_frames = NULL;
  self->swipe_frame_count = 0;
}

static void
append_swipe_frame (FpiDeviceGoodix55a2 *self)
{
  struct fpi_frame *frame = g_malloc0 (sizeof (*frame) +
                                       GOODIX55A2_IMAGE_PIXELS);

  goodix55a2_normalize (self->corrected, frame->data);
  self->swipe_frames = g_slist_prepend (self->swipe_frames, frame);
  self->swipe_frame_count++;
}

static void
submit_swipe (FpiDeviceGoodix55a2 *self)
{
  g_autoptr(FpImage) image = NULL;
  guint frame_count = self->swipe_frame_count;

  if (frame_count >= GOODIX55A2_MIN_SWIPE_FRAMES)
    {
      self->swipe_frames = g_slist_reverse (self->swipe_frames);
      image = goodix55a2_assemble_swipe (self->swipe_frames);
    }

  clear_swipe_frames (self);
  if (!image || image->height < GOODIX55A2_MIN_SWIPE_HEIGHT)
    {
      fp_dbg ("GF3206 swipe is too short (%u frames, %u pixels)",
              frame_count, image ? image->height : 0);
      fpi_image_device_retry_scan (FP_IMAGE_DEVICE (self),
                                   FP_DEVICE_RETRY_TOO_SHORT);
      return;
    }

  fp_dbg ("GF3206 assembled %u frames into %ux%u",
          frame_count, image->width, image->height);
  image->ppmm = GOODIX55A2_PPMM;
  image->flags |= FPI_IMAGE_PARTIAL;
  fpi_image_device_image_captured (FP_IMAGE_DEVICE (self),
                                   g_steal_pointer (&image));
}

enum scan_states
{
  SCAN_CAPTURE,
  SCAN_PROCESS,
  SCAN_NUM_STATES,
};

static void
scan_run_state (FpiSsm *ssm,
                FpDevice *device)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);

  self->scan_delayed = FALSE;
  if (self->deactivating)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_CAPTURE:
      start_capture (ssm);
      break;

    case SCAN_PROCESS:
      {
        gdouble mean;
        gdouble active_fraction;

        goodix55a2_flat_field (self->raw, self->baseline, self->kr_q13,
                               self->corrected);
        goodix55a2_finger_metrics (self->corrected, &mean,
                                   &active_fraction);
        fp_dbg ("GF3206 finger metrics: mean %.2f active %.3f",
                mean, active_fraction);

        if (self->state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
          {
            gboolean present = mean >= GOODIX55A2_FINGER_ON_MEAN &&
                               active_fraction >=
                                 GOODIX55A2_FINGER_ON_FRACTION;

            self->finger_on_count = present ? self->finger_on_count + 1 : 0;
            if (self->finger_on_count >= GOODIX55A2_FINGER_ON_FRAMES)
              {
                clear_swipe_frames (self);
                self->finger_off_count = 0;
                fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self),
                                                       TRUE);
              }
          }

        if (self->state == FPI_IMAGE_DEVICE_STATE_CAPTURE)
          {
            gboolean absent = mean <= GOODIX55A2_FINGER_OFF_MEAN ||
                              active_fraction <=
                                GOODIX55A2_FINGER_OFF_FRACTION;

            self->finger_off_count = absent ? self->finger_off_count + 1 : 0;
            if (!absent)
              append_swipe_frame (self);

            if (self->finger_off_count >= GOODIX55A2_FINGER_OFF_FRAMES)
              {
                submit_swipe (self);
                if (self->state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF)
                  fpi_image_device_report_finger_status (
                    FP_IMAGE_DEVICE (self), FALSE);
                fpi_ssm_mark_completed (ssm);
                return;
              }

            if (self->swipe_frame_count >= GOODIX55A2_MAX_SWIPE_FRAMES)
              submit_swipe (self);
          }

        if (self->state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF)
          {
            gboolean absent = mean <= GOODIX55A2_FINGER_OFF_MEAN ||
                              active_fraction <=
                                GOODIX55A2_FINGER_OFF_FRACTION;

            self->finger_off_count = absent ? self->finger_off_count + 1 : 0;
            if (self->finger_off_count >= GOODIX55A2_FINGER_OFF_FRAMES)
              {
                fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self),
                                                       FALSE);
                fpi_ssm_mark_completed (ssm);
                return;
              }
          }

        if (self->deactivating ||
            self->state == FPI_IMAGE_DEVICE_STATE_IDLE ||
            self->state == FPI_IMAGE_DEVICE_STATE_INACTIVE)
          fpi_ssm_mark_completed (ssm);
        else
          {
            self->scan_delayed = TRUE;
            jump_to_capture_at_rate (ssm, SCAN_CAPTURE);
          }
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void start_scan (FpiDeviceGoodix55a2 *self);

static void
scan_complete (FpiSsm *ssm,
               FpDevice *device,
               GError *error)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);

  self->scan_ssm = NULL;
  self->scan_delayed = FALSE;

  if (self->deactivating)
    {
      clear_swipe_frames (self);
      g_clear_error (&error);
      fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (self), NULL);
    }
  else if (error)
    fpi_image_device_session_error (FP_IMAGE_DEVICE (self), error);
  else if (self->state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON ||
           self->state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF ||
           self->state == FPI_IMAGE_DEVICE_STATE_CAPTURE)
    start_scan (self);
}

static void
start_scan (FpiDeviceGoodix55a2 *self)
{
  if (self->scan_ssm || self->deactivating)
    return;

  self->scan_ssm = fpi_ssm_new (FP_DEVICE (self), scan_run_state,
                                SCAN_NUM_STATES);
  fpi_ssm_start (self->scan_ssm, scan_complete);
}

static void
dev_activate (FpImageDevice *device)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);

  if (!self->tls_ready || !self->calibration_valid)
    {
      fpi_image_device_activate_complete (
        device,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                  "GF3206 session is not initialized"));
      return;
    }

  self->deactivating = FALSE;
  g_clear_object (&self->io_cancellable);
  self->io_cancellable = g_cancellable_new ();
  self->finger_on_count = 0;
  self->finger_off_count = 0;
  clear_swipe_frames (self);
  fpi_image_device_activate_complete (device, NULL);
}

static void
dev_deactivate (FpImageDevice *device)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);

  self->deactivating = TRUE;
  clear_swipe_frames (self);
  if (self->io_cancellable)
    g_cancellable_cancel (self->io_cancellable);

  if (!self->scan_ssm)
    {
      fpi_image_device_deactivate_complete (device, NULL);
      return;
    }

  if (self->scan_delayed)
    {
      fpi_ssm_cancel_delayed_state_change (self->scan_ssm);
      self->scan_delayed = FALSE;
      fpi_ssm_mark_completed (self->scan_ssm);
    }
}

static void
dev_change_state (FpImageDevice *device,
                  FpiImageDeviceState state)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (device);

  self->state = state;
  switch (state)
    {
    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON:
      clear_swipe_frames (self);
      self->finger_on_count = 0;
      start_scan (self);
      break;

    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF:
      self->finger_off_count = 0;
      start_scan (self);
      break;

    case FPI_IMAGE_DEVICE_STATE_CAPTURE:
      start_scan (self);
      break;

    case FPI_IMAGE_DEVICE_STATE_INACTIVE:
    case FPI_IMAGE_DEVICE_STATE_ACTIVATING:
    case FPI_IMAGE_DEVICE_STATE_IDLE:
    case FPI_IMAGE_DEVICE_STATE_DEACTIVATING:
      break;
    }
}

static const FpIdEntry id_table[] = {
  { .vid = 0x27c6, .pid = 0x55a2 },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_goodix55a2_init (FpiDeviceGoodix55a2 *self)
{
  self->rx_buffer = g_byte_array_new ();
  self->baseline = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  self->kr_q13 = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  self->raw = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  self->corrected = g_new (guint16, GOODIX55A2_IMAGE_PIXELS);
  self->state = FPI_IMAGE_DEVICE_STATE_INACTIVE;
}

static void
fpi_device_goodix55a2_finalize (GObject *object)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (object);

  tls_clear (self);
  g_clear_object (&self->io_cancellable);
  g_clear_pointer (&self->rx_buffer, g_byte_array_unref);
  g_clear_pointer (&self->last_replies, g_ptr_array_unref);
  g_clear_pointer (&self->calibration_frames, g_free);
  g_clear_pointer (&self->baseline, g_free);
  g_clear_pointer (&self->kr_q13, g_free);
  g_clear_pointer (&self->raw, g_free);
  g_clear_pointer (&self->corrected, g_free);
  clear_swipe_frames (self);

  G_OBJECT_CLASS (fpi_device_goodix55a2_parent_class)->finalize (object);
}

static void
fpi_device_goodix55a2_class_init (FpiDeviceGoodix55a2Class *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *image_class = FP_IMAGE_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_goodix55a2_finalize;

  device_class->id = FP_COMPONENT;
  device_class->full_name = "Goodix GF3206";
  device_class->type = FP_DEVICE_TYPE_USB;
  device_class->id_table = id_table;
  device_class->scan_type = FP_SCAN_TYPE_SWIPE;

  image_class->img_width = GOODIX55A2_ASSEMBLED_WIDTH;
  image_class->img_height = -1;
  image_class->img_open = dev_open;
  image_class->img_close = dev_close;
  image_class->activate = dev_activate;
  image_class->deactivate = dev_deactivate;
  image_class->change_state = dev_change_state;
}
