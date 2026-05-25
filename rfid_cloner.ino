/**
 * RFID Card Cloner v2.0
 *
 * Три режима работы (переключение кнопкой на Pin A0):
 *   DETECT  — определение типа карты, UID, статуса чтения/клонирования
 *   READ   — чтение всех секторов MIFARE Classic 1K/4K в память Arduino
 *   WRITE  — запись дампа на пустую CUID-карту
 *
 * Wiring:
 *   RC522:    SDA=10, SCK=13, MOSI=11, MISO=12, RST=9, 3.3V
 *   LCD 16x2: RS=7, E=6, D4=5, D5=4, D6=3, D7=2
 *             VDD=5V, GND, VO=10k pot, BLA=5V(220R), BLK=GND
 *   Button:   Pin A0 → GND (внутренний pull-up)
 *
 * Для клонирования MIFARE Classic:
 *   1) Пустая CUID-карта (Chinese UID Changeable) — перезаписываемый UID
 *   2) Стандартные ключи: A = FF FF FF FF FF FF, B = FF FF FF FF FF FF
 *   3) Если ключи нестандартные — sectors[] покажут какие не прочитались
 *
 * Ограничения Arduino Uno (2 КБ SRAM):
 *   MIFARE Classic 1K:  16 sectors × 4 blocks × 16 bytes = 1024 bytes — влезает
 *   MIFARE Classic 4K: 40 sectors × 4 blocks × 16 bytes = 2560 bytes — НЕ влезает!
 *     Для 4K используется partial dump (только первые 16 секторов = 1024 bytes)
 *
 * Компиляция:
 *   arduino-cli compile --fqbn arduino:avr:uno rfid_cloner.ino
 */

#include <SPI.h>
#include <MFRC522.h>
#include <LiquidCrystal.h>

// ===================== ПИНЫ =====================

#define SS_PIN    10   // RC522 SDA
#define RST_PIN   9    // RC522 RST
#define BTN_PIN   A0   // Кнопка переключения режима

// LCD: RS=7, E=6, D4=5, D5=4, D6=3, D7=2
LiquidCrystal lcd(7, 6, 5, 4, 3, 2);
MFRC522      mfrc522(SS_PIN, RST_PIN);

// ===================== РЕЖИМЫ =====================

enum Mode { MODE_DETECT, MODE_READ, MODE_WRITE };
Mode currentMode = MODE_DETECT;

const char* modeNames[]  = {"DETECT", "READ", "WRITE"};
const char* modeDesc[]   = {
  "Card type detect",
  "Read card sectors",
  "Write to CUID"
};

// ===================== ДАННЫЕ КАРТЫ (DETECT) =====================

byte lastUid[10]     = {0};
byte lastUidLen      = 0;
byte lastSak          = 0;
byte lastAtqa[2]      = {0, 0};

String cardType       = "";
String readStatus     = "";
String cloneStatus    = "";

bool     cardActive   = false;
unsigned long cardTime = 0;
byte     screenPhase  = 0;

// ===================== ДАМП КАРТЫ (READ/WRITE) =====================

// MIFARE Classic 1K: 16 секторов × 4 блока × 16 байт = 1024 байта
#define MAX_SECTORS  16
#define BLOCKS_PER_SECTOR 4
#define BLOCK_SIZE   16

byte cardDump[MAX_SECTORS][BLOCKS_PER_SECTOR][BLOCK_SIZE];
// Состояние каждого сектора: 0 = не прочитан, 1 = OK, 2 = auth fail, 3 = read fail
byte sectorStatus[MAX_SECTORS];
bool dumpReady = false;
byte dumpSectorsCount = 0;  // Сколько секторов в дампе (1K=16, 4K=16 partial)

// Стандартные ключи доступа
MFRC522::MIFARE_Key keyDefault;
// Для брутфорса — список распространённых ключей
const byte commonKeys[][6] = {
  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},  // Фабричный (самый частый)
  {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},  // NXP MAD
  {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},  // NXP MAD
  {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},  // Китайские карты
  {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6},
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A},
  {0x71, 0x8C, 0x1E, 0xE1, 0x30, 0x39},  // MF Classic default B
  {0x88, 0x29, 0x47, 0x76, 0x03, 0x59},
  {0x47, 0x2B, 0x52, 0x0D, 0x5C, 0x2E},
};
const byte numCommonKeys = sizeof(commonKeys) / sizeof(commonKeys[0]);

// ===================== КНОПКА =====================

unsigned long lastBtnPress = 0;
const unsigned long DEBOUNCE = 300;

// ===================== CARD INFO (DETECT MODE) =====================

struct CardInfo {
  const char* name;
  const char* rd;
  const char* cl;
};

CardInfo identifyCard(byte sak, byte atqa0, byte atqa1) {
  if (sak == 0x08 && atqa0 == 0x04 && atqa1 == 0x00)
    return {"MF Classic 1K",  "Read: YES", "Clone: YES"};
  if (sak == 0x18 && atqa0 == 0x04 && atqa1 == 0x00)
    return {"MF Classic 4K",  "Read: PART", "Clone: LIM"};
  if (sak == 0x09)
    return {"MF Mini",        "Read: YES", "Clone: YES"};
  if (sak == 0x04 && atqa0 == 0x44 && atqa1 == 0x00)
    return {"MF Ultralight",  "Read: YES", "Clone: YES"};
  if (sak == 0x44)
    return {"MF UltralightC", "Read: PART", "Clone: NO"};
  if (sak == 0x20)
    return {"MF DESFire",     "Read: LIM",  "Clone: NO"};
  if (sak == 0x38)
    return {"MF Plus 2/4",    "Read: PART", "Clone: NO"};
  if (sak == 0x00 && atqa0 == 0x44 && atqa1 == 0x00)
    return {"NTAG 2xx",       "Read: YES",  "Clone: YES"};
  return {"Unknown",          "Read: ??",   "Clone: ??"};
}

// ===================== LCD HELPERS =====================

void showMode() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("[");
  lcd.print(modeNames[currentMode]);
  lcd.print("] ");
  lcd.print(modeDesc[currentMode]);
}

void showIdle() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("[");
  lcd.print(modeNames[currentMode]);
  lcd.print("] Ready...");
  lcd.setCursor(0, 1);
  lcd.print("Apply card");
}

void showCardInfo() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(cardType);
  lcd.setCursor(0, 1);
  String uidStr = "";
  if (lastUidLen <= 4) {
    for (byte i = 0; i < lastUidLen; i++) {
      if (lastUid[i] < 0x10) uidStr += "0";
      uidStr += String(lastUid[i], HEX);
    }
  } else {
    uidStr = "..";
    int startByte = lastUidLen - 5;
    for (byte i = startByte; i < lastUidLen; i++) {
      if (lastUid[i] < 0x10) uidStr += "0";
      uidStr += String(lastUid[i], HEX);
    }
  }
  uidStr.toUpperCase();
  lcd.print("UID:" + uidStr);
}

void showStatus() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(readStatus);
  lcd.setCursor(0, 1);
  lcd.print(cloneStatus);
}

void showProgress(const char* action, int current, int total) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(action);
  lcd.setCursor(0, 1);
  lcd.print(current);
  lcd.print("/");
  lcd.print(total);
  lcd.print(" sectors");

  // Индикатор прогресса из 16 символов
  // Не используем lcd.setCursor, чтобы не перезаписывать цифры
  // Но можно добавить простую полосу после цифр
}

void showResult(const char* line1, const char* line2) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(line1);
  lcd.setCursor(0, 1);
  lcd.print(line2);
}

// ===================== SERIAL =====================

void printCardInfo() {
  Serial.println("======== Card Detected ========");
  Serial.print("  Type:  "); Serial.println(cardType);
  Serial.print("  SAK:   0x"); Serial.println(lastSak, HEX);
  Serial.print("  ATQA:  0x"); Serial.print(lastAtqa[0], HEX);
  Serial.print(" 0x"); Serial.println(lastAtqa[1], HEX);
  Serial.print("  UID:   ");
  for (byte i = 0; i < lastUidLen; i++) {
    if (lastUid[i] < 0x10) Serial.print("0");
    Serial.print(lastUid[i], HEX);
    if (i < lastUidLen - 1) Serial.print(" ");
  }
  Serial.println();
  Serial.print("  "); Serial.print(readStatus);
  Serial.print("  |  "); Serial.println(cloneStatus);
  Serial.println("===============================");
}

/**
 * Вывод дампа сектора в Serial (hex).
 */
void printSectorDump(byte sector) {
  Serial.print("  Sector ");
  if (sector < 10) Serial.print(" ");
  Serial.print(sector);
  Serial.print(": ");

  byte status = sectorStatus[sector];
  if (status == 0) {
    Serial.println("(empty)");
    return;
  }
  if (status == 2) {
    Serial.println("(AUTH FAILED)");
    return;
  }
  if (status == 3) {
    Serial.println("(READ ERROR)");
    return;
  }

  // status == 1 (OK)
  for (byte b = 0; b < BLOCKS_PER_SECTOR; b++) {
    Serial.print("    Block ");
    if (b < 10) Serial.print(" ");
    Serial.print(sector * BLOCKS_PER_SECTOR + b);
    Serial.print(": ");
    for (byte j = 0; j < BLOCK_SIZE; j++) {
      if (cardDump[sector][b][j] < 0x10) Serial.print("0");
      Serial.print(cardDump[sector][b][j], HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
}

/**
 * Полный дамп всех секторов в Serial.
 */
void printFullDump() {
  Serial.println("\n======== Card Dump ========");
  Serial.print("  Sectors: ");
  Serial.print(dumpSectorsCount);
  Serial.println();
  for (byte s = 0; s < dumpSectorsCount; s++) {
    printSectorDump(s);
  }
  Serial.println("===========================\n");
}

// ===================== АВТОРИЗАЦИЯ С БРУТФОРСОМ =====================

/**
 * Попытка аутентификации в сектор с несколькими ключами.
 * Возвращает true если хотя бы один ключ подошёл.
 * Сохраняет успешный ключ в keyOut.
 */
bool authSector(byte sector, MFRC522::MIFARE_Key* keyOut) {
  byte trailerBlock = sector * BLOCKS_PER_SECTOR + 3;

  for (byte k = 0; k < numCommonKeys; k++) {
    memcpy(keyOut->keyByte, commonKeys[k], 6);

    // Пробуем Key A
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, keyOut, &(mfrc522.uid)
    );
    if (status == MFRC522::STATUS_OK) {
      Serial.print("  Sector "); Serial.print(sector);
      Serial.print(" auth OK (Key A #"); Serial.print(k); Serial.println(")");
      return true;
    }

    // Пробуем Key B
    status = mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, keyOut, &(mfrc522.uid)
    );
    if (status == MFRC522::STATUS_OK) {
      Serial.print("  Sector "); Serial.print(sector);
      Serial.print(" auth OK (Key B #"); Serial.print(k); Serial.println(")");
      return true;
    }
  }

  Serial.print("  Sector "); Serial.print(sector);
  Serial.println(" auth FAILED (all keys)");
  return false;
}

// ===================== ЧТЕНИЕ КАРТЫ (READ MODE) =====================

/**
 * Определяет сколько секторов у карты по типу.
 */
byte getSectorCount() {
  // MIFARE Classic 1K: SAK=0x08, 16 секторов
  // MIFARE Classic 4K: SAK=0x18, 40 секторов (но мы читаем только 16)
  // MIFARE Mini: SAK=0x09, 5 секторов (20 блоков)
  if (lastSak == 0x09) return 5;   // Mini
  if (lastSak == 0x18) return 16;  // 4K partial (не влезает в RAM)
  return 16;  // 1K и по умолчанию
}

/**
 * Читает все секторы MIFARE Classic карты.
 * Предполагается, что карта уже выбрана (PICC_Select).
 */
bool readMifareClassic() {
  dumpSectorsCount = getSectorCount();
  MFRC522::MIFARE_Key authKey;

  Serial.println("\n--- Reading MIFARE Classic ---");

  for (byte s = 0; s < dumpSectorsCount; s++) {
    // Обновляем прогресс на LCD
    showProgress("Reading", s + 1, dumpSectorsCount);

    // Аутентификация
    if (!authSector(s, &authKey)) {
      sectorStatus[s] = 2;  // auth failed
      // Перезапускаем карту для следующего сектора
      mfrc522.PICC_HaltA();
      delay(50);
      byte atqa[2];
      byte atqaSize = sizeof(atqa);
      mfrc522.PICC_WakeupA(atqa, &atqaSize);
      if (mfrc522.PICC_Select(&mfrc522.uid, 0) != MFRC522::STATUS_OK) {
        Serial.println("  Card lost during read!");
        return false;
      }
      continue;
    }

    // Читаем 4 блока сектора
    bool allOk = true;
    for (byte b = 0; b < BLOCKS_PER_SECTOR; b++) {
      byte blockNum = s * BLOCKS_PER_SECTOR + b;
      byte buf[BLOCK_SIZE + 2];  // +2 для CRC
      byte sz = sizeof(buf);

      MFRC522::StatusCode status = mfrc522.MIFARE_Read(blockNum, buf, &sz);
      if (status == MFRC522::STATUS_OK) {
        memcpy(cardDump[s][b], buf, BLOCK_SIZE);
      } else {
        Serial.print("  Block "); Serial.print(blockNum);
        Serial.print(" read error: ");
        Serial.println(mfrc522.GetStatusCodeName(status));
        allOk = false;
      }
    }

    sectorStatus[s] = allOk ? 1 : 3;

    // Перезапускаем карту для следующего сектора
    mfrc522.PICC_HaltA();
    delay(50);
    byte atqa[2];
    byte atqaSize = sizeof(atqa);
    mfrc522.PICC_WakeupA(atqa, &atqaSize);
    if (mfrc522.PICC_Select(&mfrc522.uid, 0) != MFRC522::STATUS_OK) {
      Serial.println("  Card lost during read!");
      // Но сохраняем что успели прочитать
      break;
    }
  }

  // Считаем успешные сектора
  byte okCount = 0;
  for (byte s = 0; s < dumpSectorsCount; s++) {
    if (sectorStatus[s] == 1) okCount++;
  }

  dumpReady = (okCount > 0);
  mfrc522.PICC_HaltA();

  printFullDump();

  return dumpReady;
}

// ===================== ЗАПИСЬ КАРТЫ (WRITE MODE) =====================

/**
 * Записывает сохранённый дамп на CUID-карту.
 * Предполагается, что карта уже выбрана (PICC_Select).
 */
bool writeMifareClassic() {
  if (!dumpReady) {
    Serial.println("ERROR: No dump in memory. READ first!");
    showResult("No dump!", "READ card first");
    return false;
  }

  MFRC522::MIFARE_Key authKey;
  memcpy(authKey.keyByte, commonKeys[0], 6);  // CUID по умолчанию принимает FF..FF

  Serial.println("\n--- Writing MIFARE Classic (CUID) ---");
  Serial.println("  Target: CUID card with default keys");
  Serial.println("  WARNING: This will OVERWRITE all sectors!\n");

  for (byte s = 0; s < dumpSectorsCount; s++) {
    if (sectorStatus[s] != 1) {
      Serial.print("  Sector "); Serial.print(s);
      Serial.println(" skipped (no data)");
      continue;
    }

    showProgress("Writing", s + 1, dumpSectorsCount);

    byte trailerBlock = s * BLOCKS_PER_SECTOR + 3;

    // Аутентификация на CUID (ключ A по умолчанию FF..FF)
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &authKey, &(mfrc522.uid)
    );

    if (status != MFRC522::STATUS_OK) {
      Serial.print("  Sector "); Serial.print(s);
      Serial.print(" auth failed: ");
      Serial.println(mfrc522.GetStatusCodeName(status));
      mfrc522.PICC_HaltA();
      showResult("Auth fail!", "Sector ");
      // Нужно показать номер сектора
      return false;
    }

    // Пишем 4 блока сектора
    bool allOk = true;
    for (byte b = 0; b < BLOCKS_PER_SECTOR; b++) {
      byte blockNum = s * BLOCKS_PER_SECTOR + b;

      // Для блока 0 сектора 0 (UID блока) — стандартный MIFARE_Write
      // работает только на CUID/FUID картах (у обычных карт Block 0 read-only)
      status = mfrc522.MIFARE_Write(blockNum, cardDump[s][b], BLOCK_SIZE);
      if (status != MFRC522::STATUS_OK) {
        Serial.print("  Block "); Serial.print(blockNum);
        Serial.print(" write error: ");
        Serial.println(mfrc522.GetStatusCodeName(status));
        allOk = false;
      } else {
        Serial.print("  Block "); Serial.print(blockNum);
        Serial.println(" written OK");
      }
    }

    if (!allOk) {
      Serial.print("  Sector "); Serial.print(s);
      Serial.println(" partially written!");
    }

    // Перезапускаем карту для следующего сектора
    mfrc522.PICC_HaltA();
    delay(100);
    byte atqa[2];
    byte atqaSize = sizeof(atqa);
    mfrc522.PICC_WakeupA(atqa, &atqaSize);
    if (mfrc522.PICC_Select(&mfrc522.uid, 0) != MFRC522::STATUS_OK) {
      Serial.println("  Card lost during write!");
      showResult("Card lost!", "Check CUID card");
      return false;
    }
  }

  mfrc522.PICC_HaltA();
  Serial.println("\n--- Write complete ---");
  showResult("Write done!", "Verify: DETECT");
  return true;
}

// ===================== TYPE A CARD PROCESSING =====================

void processCardTypeA(byte atqa[2]) {
  bool same = (lastUidLen == mfrc522.uid.size);
  if (same) {
    for (byte i = 0; i < lastUidLen; i++) {
      if (lastUid[i] != mfrc522.uid.uidByte[i]) {
        same = false;
        break;
      }
    }
  }

  if (same && currentMode == MODE_DETECT) {
    mfrc522.PICC_HaltA();
    cardActive = true;
    cardTime   = millis();
    screenPhase = 0;
    showCardInfo();
    delay(100);
    return;
  }

  // Новая карта — сохраняем данные
  lastUidLen = mfrc522.uid.size;
  lastSak    = mfrc522.uid.sak;
  for (byte i = 0; i < lastUidLen; i++) {
    lastUid[i] = mfrc522.uid.uidByte[i];
  }
  lastAtqa[0] = atqa[0];
  lastAtqa[1] = atqa[1];

  CardInfo info = identifyCard(lastSak, lastAtqa[0], lastAtqa[1]);
  cardType    = info.name;
  readStatus  = info.rd;
  cloneStatus = info.cl;

  // Вывод в Serial
  printCardInfo();

  if (currentMode == MODE_DETECT) {
    // Режим детекта — показываем информацию на LCD
    mfrc522.PICC_HaltA();
    cardActive  = true;
    cardTime    = millis();
    screenPhase = 0;
    showCardInfo();
    delay(100);

  } else if (currentMode == MODE_READ) {
    // Проверяем — это MIFARE Classic?
    if (lastSak == 0x08 || lastSak == 0x18 || lastSak == 0x09) {
      Serial.println("  Mode READ: Starting sector dump...");
      readMifareClassic();
      cardActive = true;
      cardTime = millis();
      delay(100);
    } else {
      Serial.println("  Mode READ: Not MIFARE Classic, only detect");
      showResult("Not Classic!", "Only detect mode");
      mfrc522.PICC_HaltA();
      cardActive = true;
      cardTime = millis();
      delay(100);
    }

  } else if (currentMode == MODE_WRITE) {
    // Проверяем — это CUID-карта?
    if (lastSak == 0x08) {
      Serial.println("  Mode WRITE: Writing dump to CUID...");
      writeMifareClassic();
      cardActive = true;
      cardTime = millis();
      delay(100);
    } else {
      Serial.println("  Mode WRITE: Target is not MIFARE Classic 1K");
      showResult("Wrong card!", "Need CUID 1K");
      mfrc522.PICC_HaltA();
      cardActive = true;
      cardTime = millis();
      delay(100);
    }
  }
}

// ===================== TYPE B CARD PROCESSING =====================

void processCardTypeB(byte atqb[], byte atqbLen) {
  Serial.println("======== Type B Card Detected ========");
  Serial.print("  ATQB raw ("); Serial.print(atqbLen); Serial.print(" bytes): ");
  for (byte i = 0; i < atqbLen; i++) {
    if (atqb[i] < 0x10) Serial.print("0");
    Serial.print(atqb[i], HEX);
    Serial.print(" ");
  }
  Serial.println();

  cardType    = "ISO 14443-B";
  readStatus  = "Read: LIM";
  cloneStatus = "Clone: NO";

  lastUidLen = 4;
  for (byte i = 0; i < 4 && (1 + i) < atqbLen; i++) {
    lastUid[i] = atqb[1 + i];
  }

  mfrc522.PICC_HaltA();
  cardActive  = true;
  cardTime    = millis();
  screenPhase = 0;
  showCardInfo();
  delay(100);
}

// ===================== КНОПКА =====================

void checkButton() {
  if (digitalRead(BTN_PIN) == LOW) {
    unsigned long now = millis();
    if (now - lastBtnPress < DEBOUNCE) return;
    lastBtnPress = now;

    // Переключение режима
    currentMode = (Mode)((currentMode + 1) % 3);

    // Сброс состояния при смене режима
    cardActive = false;
    mfrc522.PICC_HaltA();

    Serial.print("\n>>> Mode: ");
    Serial.print(modeNames[currentMode]);
    Serial.print(" - ");
    Serial.println(modeDesc[currentMode]);

    showMode();
    delay(800);
    showIdle();
  }
}

// ===================== DISPLAY UPDATE =====================

void updateDisplay() {
  unsigned long elapsed = millis() - cardTime;

  if (elapsed > 8000) {
    cardActive = false;
    mfrc522.PICC_HaltA();
    showIdle();
    return;
  }

  if (currentMode == MODE_DETECT) {
    byte newPhase = (elapsed / 2500) % 2;
    if (newPhase != screenPhase) {
      screenPhase = newPhase;
      if (screenPhase == 0) showCardInfo();
      else                   showStatus();
    }
  }
  // В режиме READ/WRITE экран остаётся как есть (результат)
}

// ===================== SETUP =====================

void setup() {
  Serial.begin(115200);
  delay(100);

  // Кнопка с внутренним pull-up
  pinMode(BTN_PIN, INPUT_PULLUP);

  SPI.begin();
  mfrc522.PCD_Init();
  mfrc522.PCD_DumpVersionToSerial();
  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_max);

  // Ключ по умолчанию
  memcpy(keyDefault.keyByte, commonKeys[0], 6);

  lcd.begin(16, 2);
  showMode();
  delay(1000);
  showIdle();

  Serial.println("\nRFID Card Cloner v2.0 Ready");
  Serial.println("Modes: DETECT / READ / WRITE (button on A0)");
  Serial.println("Antenna gain: MAX (0xFF)\n");
}

// ===================== LOOP =====================

void loop() {
  // Проверяем кнопку
  checkButton();

  // Если карта активна — обновляем экран
  if (cardActive) {
    updateDisplay();
    delay(50);
    return;
  }

  // --- Шаг 1: Wake-Up Type A ---
  byte atqa[2];
  byte atqaSize = sizeof(atqa);
  MFRC522::StatusCode statusA = mfrc522.PICC_WakeupA(atqa, &atqaSize);

  if (statusA == MFRC522::STATUS_OK) {
    if (mfrc522.PICC_Select(&mfrc522.uid, 0) == MFRC522::STATUS_OK) {
      processCardTypeA(atqa);
      return;
    }
  }

  // --- Шаг 2: Type B ---
  byte reqB[] = {0x05, 0x00, 0x00, 0x00, 0x00};
  byte atqb[20];
  byte atqbLen = sizeof(atqb);
  byte validBits = 0;
  MFRC522::StatusCode statusB = mfrc522.PCD_TransceiveData(
    reqB, sizeof(reqB), atqb, &atqbLen, &validBits, 0, true
  );
  if (statusB == MFRC522::STATUS_OK && atqbLen >= 5) {
    processCardTypeB(atqb, atqbLen);
    return;
  }

  delay(50);
}
