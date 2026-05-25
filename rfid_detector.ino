/**
 * RFID Card Type Detector v1.1
 *
 * Определяет тип поднесённой RFID-карты по SAK + ATQA,
 * показывает на LCD 16x2:
 *   Экран 1 (2.5 с): тип карты + UID
 *   Экран 2 (2.5 с): Read: YES/PART/LIM/NO  и  Clone: YES/NO
 *
 * Wiring (по схеме):
 *   RC522:  SDA=10, SCK=13, MOSI=11, MISO=12, RST=9, 3.3V
 *   LCD16x2: RS=7, E=6, D4=5, D5=4, D6=3, D7=2
 *           VDD=5V, GND, VO=10k pot, BLA=5V(220R), BLK=GND
 *
 * Поддерживаемые типы:
 *   MIFARE Classic 1K     — чтение полностью, клонирование (FUID)
 *   MIFARE Classic 4K     — чтение полностью, клонирование (FUID)
 *   MIFARE Mini           — чтение полностью, клонирование (FUID)
 *   MIFARE Ultralight     — чтение полностью, клонирование (пустая карта)
 *   MIFARE Ultralight C   — чтение частично, клонирование невозможно
 *   MIFARE DESFire        — чтение ограничено, клонирование невозможно
 *   MIFARE Plus 2/4       — чтение частично, клонирование невозможно
 *   NTAG 213/215/216      — чтение полностью, клонирование (пустая NTAG)
 *   ISO 14443-B           — чтение ограничено, клонирование невозможно
 *
 * v1.1: усиленная антенна (0x14→0xFF), попытка Type B,
 *       диагностика 125 кГц карт в Serial.
 *
 * Компиляция:
 *   arduino-cli compile --fqbn arduino:avr:uno arduino_uno/rfid_detector.ino
 */

#include <SPI.h>
#include <MFRC522.h>
#include <LiquidCrystal.h>

// ===================== ПИНЫ =====================

#define SS_PIN  10    // RC522 SDA
#define RST_PIN 9     // RC522 RST

// LCD: RS=7, E=6, D4=5, D5=4, D6=3, D7=2
LiquidCrystal lcd(7, 6, 5, 4, 3, 2);
MFRC522      mfrc522(SS_PIN, RST_PIN);

// ===================== ДАННЫЕ КАРТЫ =====================

byte lastUid[10]     = {0};
byte lastUidLen      = 0;
byte lastSak          = 0;
byte lastAtqa[2]      = {0, 0};

String cardType       = "";
String readStatus     = "";
String cloneStatus    = "";

bool     cardActive   = false;
unsigned long cardTime = 0;
byte     screenPhase  = 0;      // 0 = тип+UID, 1 = статус

// ===================== ОПРЕДЕЛЕНИЕ ТИПА =====================

/**
 * Структура с описанием карты.
 */
struct CardInfo {
  const char* name;    // название для LCD
  const char* rd;      // статус чтения
  const char* cl;      // статус клонирования
};

/**
 * Определяет тип карты по SAK и ATQA.
 *
 * SAK (Select Acknowledge) — уникален для каждого семейства MIFARE/NTAG.
 * ATQA (Answer To Request type A) — дополняет SAK для точности.
 */
CardInfo identifyCard(byte sak, byte atqa0, byte atqa1) {
  // MIFARE Classic 1K: SAK=0x08, ATQA=0x0004
  if (sak == 0x08 && atqa0 == 0x04 && atqa1 == 0x00)
    return {"MF Classic 1K",  "Read: YES", "Clone: YES"};

  // MIFARE Classic 4K: SAK=0x18, ATQA=0x0004
  if (sak == 0x18 && atqa0 == 0x04 && atqa1 == 0x00)
    return {"MF Classic 4K",  "Read: YES", "Clone: YES"};

  // MIFARE Mini: SAK=0x09
  if (sak == 0x09)
    return {"MF Mini",        "Read: YES", "Clone: YES"};

  // MIFARE Ultralight / EV1: SAK=0x04, ATQA=0x0044
  if (sak == 0x04 && atqa0 == 0x44 && atqa1 == 0x00)
    return {"MF Ultralight",  "Read: YES", "Clone: YES"};

  // MIFARE Ultralight C: SAK=0x44 (AES-шифрование)
  if (sak == 0x44)
    return {"MF UltralightC", "Read: PART", "Clone: NO"};

  // MIFARE DESFire / EV1/EV2: SAK=0x20
  if (sak == 0x20)
    return {"MF DESFire",     "Read: LIM", "Clone: NO"};

  // MIFARE Plus S / X 2K/4K: SAK=0x38
  if (sak == 0x38)
    return {"MF Plus 2/4",    "Read: PART", "Clone: NO"};

  // NTAG 213/215/216: SAK=0x00, ATQA=0x0044
  if (sak == 0x00 && atqa0 == 0x44 && atqa1 == 0x00)
    return {"NTAG 2xx",       "Read: YES", "Clone: YES"};

  // Неизвестная карта
  return {"Unknown",          "Read: ??",  "Clone: ??"};
}

// ===================== ОТРИСОВКА LCD =====================

/**
 * Стартовый экран — ожидание карты.
 */
void showIdle() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Ready...");
  lcd.setCursor(0, 1);
  lcd.print("Apply card");
}

/**
 * Экран 1: тип карты + UID.
 * UID 4 байта — полностью; 7+ байт — последние 5 с префиксом "..".
 */
void showCardInfo() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(cardType);

  lcd.setCursor(0, 1);
  String uidStr = "";
  if (lastUidLen <= 4) {
    // Полный UID: "A1B2C3D4" = 8 символов, с "UID:" = 12 символов
    for (byte i = 0; i < lastUidLen; i++) {
      if (lastUid[i] < 0x10) uidStr += "0";
      uidStr += String(lastUid[i], HEX);
    }
  } else {
    // Последние 5 байт: "..D4E5F60710" = 12 символов, с "UID:" = 16 (точно влезает)
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

/**
 * Экран 2: статус чтения и клонирования.
 */
void showStatus() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(readStatus);
  lcd.setCursor(0, 1);
  lcd.print(cloneStatus);
}

/**
 * Обновление экрана: чередование экранов каждые 2.5 с,
 * через 8 с возврат в idle.
 */
void updateDisplay() {
  unsigned long elapsed = millis() - cardTime;

  if (elapsed > 8000) {
    // Таймаут — карта убрана или устарела
    cardActive = false;
    mfrc522.PICC_HaltA();
    showIdle();
    return;
  }

  // Чередование: 0..2499 мс → тип+UID, 2500..4999 → статус, и т.д.
  byte newPhase = (elapsed / 2500) % 2;
  if (newPhase != screenPhase) {
    screenPhase = newPhase;
    if (screenPhase == 0) showCardInfo();
    else                   showStatus();
  }
}

// ===================== SERIAL =====================

/**
 * Вывод полной информации о карте в Serial.
 */
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

// ===================== SETUP =====================

void setup() {
  Serial.begin(115200);
  delay(100);

  SPI.begin();
  mfrc522.PCD_Init();
  mfrc522.PCD_DumpVersionToSerial();  // версия прошивки RC522 → Serial

  // Усиление мощности антенны — максимальное (0xFF вместо дефолтного 0x14).
  // Помогает считывать карты с маленькой антенной или на большем расстоянии.
  // Если возникают ошибки чтения — можно снизить до 0x70–0x90.
  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_max);

  lcd.begin(16, 2);
  showIdle();

  Serial.println("\nRFID Card Type Detector v1.1 Ready");
  Serial.println("Antenna gain set to MAX (0xFF)\n");
}

// ===================== LOOP =====================

void loop() {
  // Если карта активна — только обновляем экран
  if (cardActive) {
    updateDisplay();
    delay(50);
    return;
  }

  // --- Шаг 1: Wake-Up Type A → получаем ATQA ---
  byte atqa[2];
  byte atqaSize = sizeof(atqa);
  MFRC522::StatusCode statusA = mfrc522.PICC_WakeupA(atqa, &atqaSize);

  if (statusA == MFRC522::STATUS_OK) {
    // --- Type A: Anticollision + Select → получаем UID и SAK ---
    if (mfrc522.PICC_Select(&mfrc522.uid, 0) == MFRC522::STATUS_OK) {
      processCardTypeA(atqa);
      return;
    }
  }

  // --- Шаг 2: Попытка Type B (REQB) через низкоуровневую передачу ---
  // CMD: 0x05 (REQB/wUPB), AFI: 0x00 (любой), N: 0x00
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

  // --- Карты нет рядом или карта 125 кГц (RC522 не умеет). ---
  // Периодически проверяем уровень сигнала антенны для диагностики.
  static unsigned long lastDiag = 0;
  if (millis() - lastDiag > 5000) {
    lastDiag = millis();
    // Проверяем, нет ли рядом 125 кГц карты: RC522 этого не умеет,
    // но можно проверить, не изменился ли уровень шума антенны.
    byte reg = mfrc522.PCD_ReadRegister(MFRC522::ComIrqReg);
    if (reg & 0x01) {
      Serial.println("[DIAG] Timer interrupt — possible interference");
    }
  }

  delay(50);
}

/**
 * Обработка карты Type A (MIFARE, NTAG и т.д.)
 */
void processCardTypeA(byte atqa[2]) {

  // Проверка «та же самая карта?»
  bool same = (lastUidLen == mfrc522.uid.size);
  if (same) {
    for (byte i = 0; i < lastUidLen; i++) {
      if (lastUid[i] != mfrc522.uid.uidByte[i]) {
        same = false;
        break;
      }
    }
  }

  if (same) {
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

  printCardInfo();
  mfrc522.PICC_HaltA();
  cardActive  = true;
  cardTime    = millis();
  screenPhase = 0;
  showCardInfo();
  delay(100);
}

/**
 * Обработка карты Type B (ISO 14443-B).
 * Выводим диагностическую информацию и показываем на LCD.
 */
void processCardTypeB(byte atqb[], byte atqbLen) {
  Serial.println("======== Type B Card Detected ========");
  Serial.print("  ATQB raw (" ); Serial.print(atqbLen); Serial.print(" bytes): ");
  for (byte i = 0; i < atqbLen; i++) {
    if (atqb[i] < 0x10) Serial.print("0");
    Serial.print(atqb[i], HEX);
    Serial.print(" ");
  }
  Serial.println();

  cardType    = "ISO 14443-B";
  readStatus  = "Read: LIM";
  cloneStatus = "Clone: NO";

  // PUPI (Pseudo-Unique PICC Identifier) в atqb[1..4]
  lastUidLen = 4;
  for (byte i = 0; i < 4 && (1 + i) < atqbLen; i++) {
    lastUid[i] = atqb[1 + i];
  }

  String uidStr = "";
  for (byte i = 0; i < 4; i++) {
    if (lastUid[i] < 0x10) uidStr += "0";
    uidStr += String(lastUid[i], HEX);
  }
  uidStr.toUpperCase();

  Serial.print("  PUPI (UID): "); Serial.println(uidStr);
  Serial.print("  "); Serial.print(readStatus);
  Serial.print("  |  "); Serial.println(cloneStatus);
  Serial.println("======================================");

  // HLTA для Type B: 0x50, 0x00
  byte hlta[] = {0x50, 0x00};
  byte dummy[1];
  byte dummyLen = 0;
  mfrc522.PCD_TransceiveData(hlta, sizeof(hlta), dummy, &dummyLen, 0, 0, false);

  cardActive  = true;
  cardTime    = millis();
  screenPhase = 0;
  showCardInfo();
  delay(100);
}
