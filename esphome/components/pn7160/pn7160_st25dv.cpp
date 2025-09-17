#include <cinttypes>
#include <memory>

#include "pn7160.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"

namespace esphome {
namespace pn7160 {

static const char *const TAG = "pn7160.st25dv";

uint8_t PN7160::read_st25dv_tag_(nfc::NfcTag &tag) {
  std::vector<uint8_t> data;
  // pages 0 to 1 contain various info we are interested in -- do one read to grab it all
  if (this->read_st25dv_bytes_(nfc::ISO15693_DATA_START_PAGE, nfc::ISO15693_PAGE_SIZE * 2, data) != nfc::STATUS_OK) {
    return nfc::STATUS_FAILED;
  }

  if (!this->is_st25dv_formatted_(data)) {
    ESP_LOGW(TAG, "Not NDEF formatted");
    return nfc::STATUS_FAILED;
  }

  uint16_t message_length;
  uint8_t message_start_index;
  if (this->find_st25dv_ndef_(data, message_length, message_start_index) != nfc::STATUS_OK) {
    ESP_LOGW(TAG, "Couldn't find NDEF message");
    return nfc::STATUS_FAILED;
  }
  ESP_LOGVV(TAG, "NDEF message length: %u, start: %u", message_length, message_start_index);

  if (message_length == 0) {
    return nfc::STATUS_FAILED;
  }
  // we already read pages 0-1 earlier -- pick up where we left off so we're not re-reading pages
  const uint16_t read_length = message_length + message_start_index > 2 ? message_length + message_start_index - 4 : 0;
  if (read_length) {
    if (read_st25dv_bytes_(2, read_length, data) !=
        nfc::STATUS_OK) {
      ESP_LOGE(TAG, "Error reading tag data");
      return nfc::STATUS_FAILED;
    }
  }
  // we need to trim off page 0 as well as any bytes ahead of message_start_index
  data.erase(data.begin(), data.begin() + message_start_index + nfc::ISO15693_PAGE_SIZE);

  tag.set_ndef_message(make_unique<nfc::NdefMessage>(data));

  return nfc::STATUS_OK;
}

uint8_t PN7160::read_st25dv_bytes_(uint8_t start_page, uint16_t num_bytes, std::vector<uint8_t> &data) {
  ESP_LOGVV(TAG, "reading %u bytes beginning page %d", num_bytes, start_page);

  const uint8_t pages_per_read = 32;
  uint8_t page_count = (num_bytes + nfc::ISO15693_PAGE_SIZE - 1) / nfc::ISO15693_PAGE_SIZE;
  nfc::NciMessage rx;
  nfc::NciMessage tx(nfc::NCI_PKT_MT_DATA, {
    nfc::ISO15693_REQ_FLAG_DR_HIGH,
    nfc::ISO15693_CMD_READ_MULTIPLE,
    0, // start page, filled in loop
    0 // page count, 
  });
  
  for (size_t i = 0; i * pages_per_read < page_count; i++) {
    // Fill nfc command start page and page count
    uint8_t current_start_page = start_page + i * pages_per_read;
    uint8_t current_read_page_count = (i+1) * pages_per_read > page_count ? page_count % pages_per_read : pages_per_read;
    tx.get_message()[tx.get_message().size() - 2] = current_start_page;
    tx.get_message()[tx.get_message().size() - 1] = current_read_page_count - 1;

    do {  // loop because sometimes we struggle here...???...
      uint16_t timeout = num_bytes;
      if (this->transceive_(tx, rx, timeout) != nfc::STATUS_OK) {
        ESP_LOGE(TAG, "Error reading tag data");
        return nfc::STATUS_FAILED;
      }
    } while (rx.get_payload_size() < current_read_page_count * nfc::ISO15693_PAGE_SIZE);
    data.insert(data.end(), rx.get_message().begin() + nfc::NCI_PKT_HEADER_SIZE + 1, 
      rx.get_message().end() - 1);
  }

  // If num_bytes is not a multiple of page size, delete excess read bytes
  if (page_count * nfc::ISO15693_PAGE_SIZE > num_bytes) {
    size_t delete_bytes_count = page_count * nfc::ISO15693_PAGE_SIZE - num_bytes;
    rx.get_message().erase(rx.get_message().end() - delete_bytes_count, rx.get_message().end());
  }

  ESP_LOGVV(TAG, "Data read: %s", nfc::format_bytes(data).c_str());

  return nfc::STATUS_OK;
}

bool PN7160::is_st25dv_formatted_(const std::vector<uint8_t> &page_0_to_1) {
  const uint8_t p1_offset = nfc::ISO15693_PAGE_SIZE;  // page 1 will begin 4 bytes into the vector

  return (page_0_to_1.size() > p1_offset + 3) &&
         ((page_0_to_1[p1_offset + 0] != 0xFF) || (page_0_to_1[p1_offset + 1] != 0xFF) ||
          (page_0_to_1[p1_offset + 2] != 0xFF) || (page_0_to_1[p1_offset + 3] != 0xFF));
}

uint16_t PN7160::read_st25dv_capacity_() {
  std::vector<uint8_t> data;
  if (this->read_st25dv_bytes_(3, nfc::MIFARE_ULTRALIGHT_PAGE_SIZE, data) == nfc::STATUS_OK) {
    ESP_LOGV(TAG, "Tag capacity is %u bytes", data[2] * 8U);
    return data[2] * 8U;
  }
  return 0;
}

uint8_t PN7160::find_st25dv_ndef_(const std::vector<uint8_t> &page_0_to_1, uint16_t &message_length,
                                             uint8_t &message_start_index) {
  const uint8_t p1_offset = nfc::ISO15693_PAGE_SIZE;  // page 2 will begin 4 bytes into the vector

  if (!(page_0_to_1.size() > p1_offset + 3)) {
    return nfc::STATUS_FAILED;
  }

  if (page_0_to_1[p1_offset + 0] == 0x03) {
    uint8_t message_length_b0 = page_0_to_1[p1_offset + 1];
    if (message_length_b0 == 0xFF) {
      message_length = (static_cast<uint16_t>(page_0_to_1[p1_offset + 2]) << 8) | page_0_to_1[p1_offset + 3];
      message_start_index = 4;
    } else {
      message_length = message_length_b0;
      message_start_index = 2;
    }
    return nfc::STATUS_OK;
  } 
  return nfc::STATUS_FAILED;
}

uint8_t PN7160::write_st25dv_tag_(std::vector<uint8_t> &uid,
                                             const std::shared_ptr<nfc::NdefMessage> &message) {
  uint32_t capacity = this->read_st25dv_capacity_();

  auto encoded = message->encode();

  uint32_t message_length = encoded.size();
  uint32_t buffer_length = nfc::get_mifare_classic_buffer_size(message_length);

  if (buffer_length > capacity) {
    ESP_LOGE(TAG, "Message length exceeds tag capacity %" PRIu32 " > %" PRIu32, buffer_length, capacity);
    return nfc::STATUS_FAILED;
  }

  encoded.insert(encoded.begin(), 0x03);
  if (message_length < 255) {
    encoded.insert(encoded.begin() + 1, message_length);
  } else {
    encoded.insert(encoded.begin() + 1, 0xFF);
    encoded.insert(encoded.begin() + 2, (message_length >> 8) & 0xFF);
    encoded.insert(encoded.begin() + 2, message_length & 0xFF);
  }
  encoded.push_back(0xFE);

  encoded.resize(buffer_length, 0);

  uint32_t index = 0;
  uint8_t current_page = nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE;

  while (index < buffer_length) {
    std::vector<uint8_t> data(encoded.begin() + index, encoded.begin() + index + nfc::MIFARE_ULTRALIGHT_PAGE_SIZE);
    if (this->write_st25dv_page_(current_page, data) != nfc::STATUS_OK) {
      return nfc::STATUS_FAILED;
    }
    index += nfc::MIFARE_ULTRALIGHT_PAGE_SIZE;
    current_page++;
  }
  return nfc::STATUS_OK;
}

uint8_t PN7160::clean_st25dv_() {
  uint32_t capacity = this->read_st25dv_capacity_();
  uint8_t pages = (capacity / nfc::MIFARE_ULTRALIGHT_PAGE_SIZE) + nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE;

  std::vector<uint8_t> blank_data = {0x00, 0x00, 0x00, 0x00};

  for (int i = nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE; i < pages; i++) {
    if (this->write_st25dv_page_(i, blank_data) != nfc::STATUS_OK) {
      return nfc::STATUS_FAILED;
    }
  }
  return nfc::STATUS_OK;
}

uint8_t PN7160::write_st25dv_page_(uint8_t page_num, std::vector<uint8_t> &write_data) {
  std::vector<uint8_t> payload = {nfc::MIFARE_CMD_WRITE_ULTRALIGHT, page_num};
  payload.insert(payload.end(), write_data.begin(), write_data.end());

  nfc::NciMessage rx;
  nfc::NciMessage tx(nfc::NCI_PKT_MT_DATA, payload);

  if (this->transceive_(tx, rx, NFCC_TAG_WRITE_TIMEOUT) != nfc::STATUS_OK) {
    ESP_LOGE(TAG, "Error writing page %u", page_num);
    return nfc::STATUS_FAILED;
  }
  return nfc::STATUS_OK;
}

}  // namespace pn7160
}  // namespace esphome
