#include <iarduino_RTC.h>
#include <SPI.h>
#include <MFRC522.h>
#include <EEPROM.h>

#define CLEAR_STATION_UID 25933
#define START_STATION_UID 4294942985

#define STATION_NUMBER 10
#define SECTOR 6      // номер сектора для записи
#define SECTOR_PART STATION_NUMBER % 2 // позиция в секторе
#define BLOCK_ADR (uint8_t)(SECTOR / 4) * 4 + 3   // позиция ключа безопастности считаем по формуле ( SECTOR // 4 * 4 + 3 )

#define RST_PIN 9
#define SS_PIN 10
#define ZUM 2

#define BASIC_STATION 0
#define FINISH_STATION 1
#define START_STATION 2
#define CLEAR_STATION 3

uint8_t MODE = FINISH_STATION;

MFRC522 rider(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;
MFRC522::StatusCode status;

iarduino_RTC time(RTC_DS1302, 7, 5, 6);

const char *strM = "JanFebMarAprMayJunJulAugSepOctNovDec";
const char *sysT = __TIME__;
const char *sysD = __DATE__;

const int time_i[6]{(sysT[6] - 48) * 10 + (sysT[7] - 48),
                    (sysT[3] - 48) * 10 + (sysT[4] - 48),
                    (sysT[0] - 48) * 10 + (sysT[1] - 48),
                    (sysD[4] - 48) * 10 + (sysD[5] - 48),
                    ((int)memmem(strM, 36, sysD, 3) + 3 - (int)&strM[0]) / 3,
                    (sysD[9] - 48) * 10 + (sysD[10] - 48)};

unsigned long getID()
{
  if (!rider.PICC_ReadCardSerial())
  {
    return 0;
  }
  unsigned long hex_num;
  hex_num = rider.uid.uidByte[0] << 8;
  hex_num += rider.uid.uidByte[1] << 8;
  hex_num += rider.uid.uidByte[2] << 8;
  hex_num += rider.uid.uidByte[3];
  rider.PICC_HaltA(); // Stop reading
  return hex_num;
}

void buzz_init()
{
  tone(ZUM, 10, 200);
}

void successful_entry()
{
  tone(ZUM, 50, 500);
}

void error()
{
  tone(ZUM, 150, 500);
  tone(ZUM, 20, 500);
  Serial.println(rider.GetStatusCodeName(status));
}

void setupKey()
{
  for (byte i = 0; i < 6; i++)
    key.keyByte[i] = 0xFF;
}

void u32to8(uint32_t value, byte *byteArray)
{
  for (uint8_t i = 0; i < 4; i++)
  {
    byteArray[3 - i] = value & 0xff;
    value >>= 8;
  }
}

uint32_t u8to32(const byte *byteArray)
{
  uint32_t value = 0;
  for (uint8_t i = 0; i < 4; ++i)
  {
    value <<= 8;
    value |= byteArray[i];
  }
  return value;
}

void dump_byte_array(byte *buffer, uint8_t len = 4)
{
  for (uint8_t i = 0; i < len; i++)
  {
    Serial.print(buffer[i]);
    Serial.print(" ");
  }
  Serial.println();
}

void prepair_array_to_write(byte *arr, const uint32_t unix)
{
  byte *unix_arr = new byte[4]{0};
  u32to8(unix, unix_arr);
  for (uint8_t i = 0; i < 4; i++)
  {
    arr[i + 4 + SECTOR_PART * 8] = unix_arr[i];
  }
  free(unix_arr);
}

bool write_rfid(byte *data)
{
  status = rider.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, BLOCK_ADR, &key, &(rider.uid));
  if (status != MFRC522::STATUS_OK)
  {
    return false;
  }

  status = rider.MIFARE_Write(SECTOR, data, 16);
  return status == MFRC522::STATUS_OK;
}

bool read_rfid(uint8_t *dataByte)
{
  status = rider.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, BLOCK_ADR, &key, &(rider.uid));
  if (status != MFRC522::STATUS_OK)
  {
    Serial.println("Auth error");
    return false;
  }

  uint8_t data[18];
  uint8_t size = sizeof(data);
  status = rider.MIFARE_Read(SECTOR, data, &size);
  if (status != MFRC522::STATUS_OK)
  {
    return false;
  }

  for (uint8_t i = 0; i < 16; i++)
  {
    dataByte[i] = data[i];
  }

  return true;
}

uint32_t read_part_u8_array(uint8_t *data, uint8_t margin = 0)
{
  uint8_t temp[4]{0};
  uint8_t j = 0;
  for (uint8_t i = 0; i < 8; i++)
  {
    uint8_t val = data[i + margin * 8];
    if (val != 0)
    {
      temp[j++] = val;
    }
  }
  if (j == 0)
  {
    return -1;
  }
  return u8to32(temp);
}

void serial_info(uint8_t num, uint32_t time)
{
  Serial.print(num);
  Serial.print("-");
  Serial.println(time);
}

bool read_rfid_serial()
{
  status = rider.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, BLOCK_ADR, &key, &(rider.uid));
  if (status != MFRC522::STATUS_OK)
  {
    Serial.println("Auth error");
    return false;
  }
  uint8_t data[18];
  uint8_t size = sizeof(data);
  uint8_t space = 0;
  for (uint8_t i = 1; i < 64; i++)
  {
    if (i % 4 != 3)
    {
      status = rider.MIFARE_Read(i, data, &size);
      if (status != MFRC522::STATUS_OK)
      {
        return false;
      }
      uint8_t st_f = space + i;
      uint8_t st_s = st_f + 1;
      uint32_t unix_f = read_part_u8_array(data);
      uint32_t unix_s = read_part_u8_array(data, 1);
      if (unix_f != -1)
      {
        serial_info(st_f, unix_f);
      }
      if (unix_s != -1)
      {
        serial_info(st_s, unix_s);
      }
    }
    if (i % 4 == 0 || i % 4 == 1 || i == 0)
    {
      space++;
    }
  }
  Serial.println("end");
  return true;
}

void dump_to_serial() {
  rider.PICC_DumpToSerial(&(rider.uid));
  successful_entry();
}

bool is_writed(uint8_t *data)
{
  for (uint8_t i = 0; i < 8; i++)
  {
    uint8_t index = i + (SECTOR_PART == 0 ? 0 : 8);
    if (data[index] != 0)
    {
      return false;
    }
  }
  return true;
}

void clear_sector(uint8_t *data)
{
  for (uint8_t i = 0; i < 8; i++)
  {
    uint8_t index = i + (SECTOR_PART == 0 ? 0 : 8);
    data[index] = 0;
  }
}

void union_u8_arrays(uint8_t *to_write, uint8_t *temp)
{
  for (uint8_t i = 0; i < 8; i++)
  {
    uint8_t index = i + (SECTOR_PART == 0 ? 0 : 8);
    to_write[index] = temp[index];
  }
}

void reload_rfid()
{
  digitalWrite(RST_PIN, HIGH); // Сбрасываем модуль
  delayMicroseconds(2);        // Ждем 2 мкс
  digitalWrite(RST_PIN, LOW);  // Отпускаем сброс
  rider.PCD_Init();
}

void process_card()
{
  uint8_t *read_data = new uint8_t[16];
  Serial.println("Go");

  if (read_rfid(read_data))
  {
    if (!is_writed(read_data))
    {
      clear_sector(read_data);
    }
    else
    {
      uint8_t *arr = new uint8_t[16]{0};
      prepair_array_to_write(arr, time.gettimeUnix());
      union_u8_arrays(read_data, arr);
      free(arr);
    }

    if (!write_rfid(read_data))
    {
      error();
    } else {
      successful_entry();
    }
  }
  else
  {
    error();
  }

  free(read_data);
}

void clear_card()
{
  for (uint8_t i = 0; i < 64; i++)
  {
  }
}

void indicate_mode()
{
  for (uint8_t i = 0; i < MODE + 1; i++)
  {
    buzz_init();
    delay(150);
  }

  if (MODE == BASIC_STATION) {
    for (size_t i = 0; i < STATION_NUMBER; i++)
    {
      tone(ZUM, 800, 100);
      delay(100);
    }
  }
}

void erase_all_data() {
  uint8_t buffer[18];
  status = rider.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 
                                  3, &key, 
                                  &(rider.uid));
  if (status != MFRC522::STATUS_OK)
  {
    error();
    return;
  }

  for (size_t i = 1; i < 64; i++)
  {
    if ((i + 1) % 4 == 0) {
      status = rider.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, i + 4, &key, &(rider.uid));
    }
    else {
      status = rider.MIFARE_Write(i, buffer, 16);
      if (status != MFRC522::STATUS_OK)
      {
        error();
        return;
      }
    }
  }

  free(buffer);
  successful_entry();
}

void setup()
{
  pinMode(3, OUTPUT);
  Serial.begin(9600);
  SPI.begin();

  rider.PCD_Init();
  rider.PCD_SetAntennaGain(rider.RxGain_max);
  rider.PCD_AntennaOff();
  rider.PCD_AntennaOn();

  time.begin();
  time.settime(time_i[0],
               time_i[1],
               time_i[2],
               time_i[3],
               time_i[4],
               time_i[5]);
  setupKey();

  // MODE = EEPROM.read(0);
  indicate_mode();
  Serial.println(MODE);
  rider.PCD_DumpVersionToSerial();
}

void loop()
{
  static uint32_t rebootTimer = millis();
  if (millis() - rebootTimer >= 15000)
  {
    rebootTimer = millis();
    reload_rfid();
  }

  if (!rider.PICC_IsNewCardPresent())
    return;
  if (!rider.PICC_ReadCardSerial())
    return;

  switch (MODE)
  {
  case START_STATION:
  {
    break;
  }
  case FINISH_STATION:
  {
    // read_rfid_serial();
    dump_to_serial();
    break;
  }
  case CLEAR_STATION:
  {
    erase_all_data();
    break;
  }
  case BASIC_STATION:
  {
    process_card();
    break;
  }
  }

  rider.PICC_HaltA();
  rider.PCD_StopCrypto1();
}