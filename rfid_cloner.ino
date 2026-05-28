/**
 * RFID Card Cloner v2.2
 *
 * Fixes:
 *   - No halt between sectors (prevents RC522 freeze)
 *   - PCD_StopCrypto1() before each re-auth
 *   - PCD_Init() after read/write to fully reset RC522
 *   - Clear "Read OK" / "Write OK" screen
 *   - Same-card detection in READ/WRITE
 *
 * Wiring:
 *   RC522:    SDA=10, SCK=13, MOSI=11, MISO=12, RST=9, 3.3V
 *   LCD 16x2: RS=7, E=6, D4=5, D5=4, D6=3, D7=2
 *   Button:   Pin A0 -> GND (internal pull-up)
 */

#include <SPI.h>
#include <MFRC522.h>
#include <LiquidCrystal.h>

#define SS_PIN   10
#define RST_PIN  9
#define BTN_PIN  A0

LiquidCrystal lcd(7, 6, 5, 4, 3, 2);
MFRC522 mfrc522(SS_PIN, RST_PIN);

enum Mode { MODE_DETECT, MODE_READ, MODE_WRITE };
Mode currentMode = MODE_DETECT;

// === Card data (detect) ===
byte lastUid[10]      = {0};
byte lastUidLen        = 0;
byte lastSak           = 0;
byte lastAtqa[2]       = {0, 0};
char cardTypeStr[20]   = "";
char readStatusStr[12] = "";
char cloneStatusStr[12]= "";

bool     cardActive  = false;
unsigned long cardTime = 0;
byte     screenPhase = 0;

// === Dump (read/write) ===
#define MAX_SECTORS  16
#define BPS          4
#define BS           16

byte cardDump[MAX_SECTORS][BPS][BS];
byte sectorStatus[MAX_SECTORS];  // 0=empty, 1=OK, 2=auth fail, 3=read err
bool dumpReady = false;
byte dumpSectorsCount = 0;

// Keys
MFRC522::MIFARE_Key keyDefault;
const byte commonKeys[][6] PROGMEM = {
  {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
  {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5},
  {0xB0,0xB1,0xB2,0xB3,0xB4,0xB5},
  {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7},
  {0xA1,0xA2,0xA3,0xA4,0xA5,0xA6},
  {0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1A,0x98,0x2C,0x7E,0x45,0x9A},
  {0x71,0x8C,0x1E,0xE1,0x30,0x39},
  {0x88,0x29,0x47,0x76,0x03,0x59},
  {0x47,0x2B,0x52,0x0D,0x5C,0x2E},
};
const byte NK = sizeof(commonKeys) / 6;

// === Button ===
unsigned long lastBtnPress = 0;

// ======================== HELPERS ========================

void resetPCD() {
  // Full RC522 reset to guarantee clean state
  mfrc522.PCD_Init();
  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_max);
}

void identifyCard(byte sak, byte atqa0, byte atqa1) {
  if (sak==0x08 && atqa0==0x04) { strcpy_P(cardTypeStr, PSTR("MF Classic 1K")); strcpy_P(readStatusStr, PSTR("Read: YES")); strcpy_P(cloneStatusStr, PSTR("Clone: YES")); }
  else if (sak==0x18 && atqa0==0x04) { strcpy_P(cardTypeStr, PSTR("MF Classic 4K")); strcpy_P(readStatusStr, PSTR("Read: PART")); strcpy_P(cloneStatusStr, PSTR("Clone: LIM")); }
  else if (sak==0x09) { strcpy_P(cardTypeStr, PSTR("MF Mini")); strcpy_P(readStatusStr, PSTR("Read: YES")); strcpy_P(cloneStatusStr, PSTR("Clone: YES")); }
  else if (sak==0x04 && atqa0==0x44) { strcpy_P(cardTypeStr, PSTR("MF Ultralight")); strcpy_P(readStatusStr, PSTR("Read: YES")); strcpy_P(cloneStatusStr, PSTR("Clone: YES")); }
  else if (sak==0x44) { strcpy_P(cardTypeStr, PSTR("MF UltralightC")); strcpy_P(readStatusStr, PSTR("Read: PART")); strcpy_P(cloneStatusStr, PSTR("Clone: NO")); }
  else if (sak==0x20) { strcpy_P(cardTypeStr, PSTR("MF DESFire")); strcpy_P(readStatusStr, PSTR("Read: LIM")); strcpy_P(cloneStatusStr, PSTR("Clone: NO")); }
  else if (sak==0x38) { strcpy_P(cardTypeStr, PSTR("MF Plus")); strcpy_P(readStatusStr, PSTR("Read: PART")); strcpy_P(cloneStatusStr, PSTR("Clone: NO")); }
  else if (sak==0x00 && atqa0==0x44) { strcpy_P(cardTypeStr, PSTR("NTAG 2xx")); strcpy_P(readStatusStr, PSTR("Read: YES")); strcpy_P(cloneStatusStr, PSTR("Clone: YES")); }
  else { strcpy_P(cardTypeStr, PSTR("Unknown")); strcpy_P(readStatusStr, PSTR("Read: ??")); strcpy_P(cloneStatusStr, PSTR("Clone: ??")); }
}

// ======================== LCD ========================

void showMode() {
  lcd.clear(); lcd.setCursor(0,0);
  if (currentMode==MODE_DETECT) lcd.print(F("[DETECT]"));
  else if (currentMode==MODE_READ) lcd.print(F("[READ]"));
  else lcd.print(F("[WRITE]"));
}

void showIdle() {
  lcd.clear(); lcd.setCursor(0,0);
  if (currentMode==MODE_DETECT) lcd.print(F("[DETECT] Ready"));
  else if (currentMode==MODE_READ) lcd.print(F("[READ] Ready"));
  else lcd.print(F("[WRITE] Ready"));
  lcd.setCursor(0,1);
  lcd.print(F("Apply card"));
}

void showCardInfo() {
  lcd.clear(); lcd.setCursor(0,0); lcd.print(cardTypeStr);
  lcd.setCursor(0,1); lcd.print(F("UID:"));
  byte show = (lastUidLen<=4) ? lastUidLen : 5;
  byte start = (lastUidLen<=4) ? 0 : lastUidLen-5;
  for (byte i=start; i<lastUidLen && i<start+5; i++) {
    if (lastUid[i]<0x10) lcd.print('0');
    lcd.print(lastUid[i], HEX);
  }
}

void showStatus() {
  lcd.clear(); lcd.setCursor(0,0); lcd.print(readStatusStr);
  lcd.setCursor(0,1); lcd.print(cloneStatusStr);
}

void showProgress(int cur, int total) {
  lcd.clear(); lcd.setCursor(0,0);
  if (currentMode==MODE_READ) lcd.print(F("Reading"));
  else lcd.print(F("Writing"));
  lcd.setCursor(0,1);
  lcd.print(cur); lcd.print(F("/")); lcd.print(total);
}

void showResult(const __FlashStringHelper *l1, const __FlashStringHelper *l2) {
  lcd.clear(); lcd.setCursor(0,0); lcd.print(l1);
  lcd.setCursor(0,1); lcd.print(l2);
}

void showReadDone(byte ok, byte total) {
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("Read OK: ")); lcd.print(ok); lcd.print(F("/")); lcd.print(total);
  lcd.setCursor(0,1);
  if (ok == total) lcd.print(F("=> Switch WRITE"));
  else { lcd.print(ok); lcd.print(F(" ok, ")); lcd.print(total-ok); lcd.print(F(" fail")); }
}

// ======================== SERIAL ========================

void printCardInfo() {
  Serial.println(F("======== Card Detected ========"));
  Serial.print(F("  Type:  ")); Serial.println(cardTypeStr);
  Serial.print(F("  SAK:   0x")); Serial.println(lastSak, HEX);
  Serial.print(F("  UID:   "));
  for (byte i=0; i<lastUidLen; i++) {
    if (lastUid[i]<0x10) Serial.print('0');
    Serial.print(lastUid[i], HEX);
    if (i<lastUidLen-1) Serial.print(' ');
  }
  Serial.println();
  Serial.print(F("  ")); Serial.print(readStatusStr);
  Serial.print(F("  |  ")); Serial.println(cloneStatusStr);
  Serial.println(F("==============================="));
}

void printSectorDump(byte s) {
  Serial.print(F("  Sector "));
  if (s<10) Serial.print(' ');
  Serial.print(s);
  if (sectorStatus[s]==0) { Serial.println(F(": (empty)")); return; }
  if (sectorStatus[s]==2) { Serial.println(F(": (AUTH FAILED)")); return; }
  if (sectorStatus[s]==3) { Serial.println(F(": (READ ERROR)")); return; }
  for (byte b=0; b<BPS; b++) {
    Serial.print(F("    Blk "));
    byte bn=s*BPS+b;
    if (bn<10) Serial.print(' ');
    Serial.print(bn); Serial.print(F(": "));
    for (byte j=0; j<BS; j++) {
      if (cardDump[s][b][j]<0x10) Serial.print('0');
      Serial.print(cardDump[s][b][j], HEX); Serial.print(' ');
    }
    Serial.println();
  }
}

void printFullDump() {
  Serial.println(F("\n======== Card Dump ========"));
  for (byte s=0; s<dumpSectorsCount; s++) printSectorDump(s);
  Serial.println(F("===========================\n"));
}

// ======================== AUTH ========================

bool authSector(byte sector, MFRC522::MIFARE_Key *keyOut) {
  mfrc522.PCD_StopCrypto1();  // Clear crypto before re-auth
  byte trailerBlock = sector*BPS+3;
  for (byte k=0; k<NK; k++) {
    memcpy_P(keyOut->keyByte, commonKeys[k], 6);
    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, keyOut, &(mfrc522.uid))==MFRC522::STATUS_OK) {
      Serial.print(F("  Sector ")); Serial.print(sector); Serial.print(F(" KeyA #")); Serial.println(k);
      return true;
    }
    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, keyOut, &(mfrc522.uid))==MFRC522::STATUS_OK) {
      Serial.print(F("  Sector ")); Serial.print(sector); Serial.print(F(" KeyB #")); Serial.println(k);
      return true;
    }
  }
  Serial.print(F("  Sector ")); Serial.print(sector); Serial.println(F(" auth FAILED"));
  return false;
}

// ======================== READ ========================

byte getSectorCount() {
  if (lastSak==0x09) return 5;
  if (lastSak==0x18) return 16;
  return 16;
}

bool readMifareClassic() {
  dumpSectorsCount = getSectorCount();
  MFRC522::MIFARE_Key authKey;
  Serial.println(F("\n--- Reading MIFARE Classic ---"));

  for (byte s=0; s<dumpSectorsCount; s++) {
    showProgress(s+1, dumpSectorsCount);

    if (!authSector(s, &authKey)) {
      sectorStatus[s]=2;
      continue;
    }

    bool ok=true;
    for (byte b=0; b<BPS; b++) {
      byte bn=s*BPS+b;
      byte buf[BS+2]; byte sz2=sizeof(buf);
      if (mfrc522.MIFARE_Read(bn,buf,&sz2)==MFRC522::STATUS_OK)
        memcpy(cardDump[s][b],buf,BS);
      else ok=false;
    }
    sectorStatus[s]=ok?1:3;
    // NO halt between sectors — just re-auth next sector
  }

  byte okCnt=0;
  for (byte s=0; s<dumpSectorsCount; s++) if(sectorStatus[s]==1) okCnt++;
  dumpReady=(okCnt>0);

  // Fully reset RC522 to guarantee clean state
  mfrc522.PCD_StopCrypto1();
  mfrc522.PICC_HaltA();
  resetPCD();

  printFullDump();
  return dumpReady;
}

// ======================== WRITE ========================

bool writeMifareClassic() {
  if (!dumpReady) {
    Serial.println(F("ERROR: No dump! READ first!"));
    showResult(F("No dump!"),F("READ first"));
    resetPCD();
    return false;
  }

  MFRC522::MIFARE_Key authKey;
  memcpy_P(authKey.keyByte, commonKeys[0], 6);
  Serial.println(F("\n--- Writing CUID ---"));

  byte writtenCnt=0;

  for (byte s=0; s<dumpSectorsCount; s++) {
    if (sectorStatus[s]!=1) continue;
    showProgress(s+1, dumpSectorsCount);

    mfrc522.PCD_StopCrypto1();  // Clear crypto before re-auth
    byte trailerBlock=s*BPS+3;
    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &authKey, &(mfrc522.uid))!=MFRC522::STATUS_OK) {
      Serial.print(F("  Sector ")); Serial.print(s); Serial.println(F(" auth FAIL, skip"));
      continue;
    }

    bool sectorOk=true;
    for (byte b=0; b<BPS; b++) {
      byte bn=s*BPS+b;
      if (mfrc522.MIFARE_Write(bn, cardDump[s][b], BS)!=MFRC522::STATUS_OK) {
        Serial.print(F("  Blk ")); Serial.print(bn); Serial.println(F(" write FAIL"));
        sectorOk=false;
      }
    }
    if (sectorOk) {
      writtenCnt++;
      Serial.print(F("  Sector ")); Serial.print(s); Serial.println(F(" OK"));
    }
    // NO halt between sectors
  }

  // Fully reset RC522
  mfrc522.PCD_StopCrypto1();
  mfrc522.PICC_HaltA();
  resetPCD();

  Serial.print(F("\n--- Write done: ")); Serial.print(writtenCnt); Serial.print(F("/")); Serial.println(dumpSectorsCount);
  return writtenCnt>0;
}

// ======================== CARD PROCESSING ========================

void processCardTypeA(byte atqa[2]) {
  bool same = (lastUidLen==mfrc522.uid.size);
  if (same) { for (byte i=0;i<lastUidLen;i++) if(lastUid[i]!=mfrc522.uid.uidByte[i]) {same=false;break;} }

  // Same card in DETECT — just show info again
  if (same && currentMode==MODE_DETECT) {
    mfrc522.PICC_HaltA(); cardActive=true; cardTime=millis(); screenPhase=0; showCardInfo(); return;
  }

  // Same card in READ/WRITE — show message, don't re-process
  if (same && currentMode!=MODE_DETECT) {
    mfrc522.PICC_HaltA();
    cardActive=true; cardTime=millis();
    showResult(F("Same card"),F("Remove first"));
    return;
  }

  // New card — save data
  lastUidLen=mfrc522.uid.size; lastSak=mfrc522.uid.sak;
  for (byte i=0;i<lastUidLen;i++) lastUid[i]=mfrc522.uid.uidByte[i];
  lastAtqa[0]=atqa[0]; lastAtqa[1]=atqa[1];
  identifyCard(lastSak, lastAtqa[0], lastAtqa[1]);
  printCardInfo();

  if (currentMode==MODE_DETECT) {
    mfrc522.PICC_HaltA(); cardActive=true; cardTime=millis(); screenPhase=0; showCardInfo();

  } else if (currentMode==MODE_READ) {
    if (lastSak==0x08||lastSak==0x18||lastSak==0x09) {
      readMifareClassic();
      // Show clear result
      byte okCnt=0;
      for (byte s=0;s<dumpSectorsCount;s++) if(sectorStatus[s]==1) okCnt++;
      showReadDone(okCnt, dumpSectorsCount);
      cardActive=true; cardTime=millis();
    } else {
      showResult(F("Not Classic!"),F("Only detect"));
      mfrc522.PICC_HaltA();
      cardActive=true; cardTime=millis();
    }

  } else if (currentMode==MODE_WRITE) {
    if (lastSak==0x08) {
      bool ok = writeMifareClassic();
      if (ok) {
        byte okCnt=0;
        for (byte s=0;s<dumpSectorsCount;s++) if(sectorStatus[s]==1) okCnt++;
        lcd.clear(); lcd.setCursor(0,0);
        lcd.print(F("Write done!"));
        lcd.setCursor(0,1);
        lcd.print(okCnt); lcd.print(F(" sectors"));
      } else {
        showResult(F("Write FAIL"),F("Check CUID"));
      }
      cardActive=true; cardTime=millis();
    } else {
      showResult(F("Wrong card!"),F("Need CUID 1K"));
      mfrc522.PICC_HaltA();
      cardActive=true; cardTime=millis();
    }
  }
}

void processCardTypeB(byte atqb[], byte atqbLen) {
  Serial.println(F("======== Type B Card ========"));
  strcpy_P(cardTypeStr, PSTR("ISO 14443-B"));
  strcpy_P(readStatusStr, PSTR("Read: LIM"));
  strcpy_P(cloneStatusStr, PSTR("Clone: NO"));
  lastUidLen=4;
  for (byte i=0;i<4&&i+1<atqbLen;i++) lastUid[i]=atqb[1+i];
  mfrc522.PICC_HaltA(); cardActive=true; cardTime=millis(); screenPhase=0; showCardInfo();
}

// ======================== BUTTON ========================

void checkButton() {
  if (digitalRead(BTN_PIN)==LOW) {
    unsigned long now=millis();
    if (now-lastBtnPress<300) return;
    lastBtnPress=now;
    currentMode=(Mode)((currentMode+1)%3);
    cardActive=false;
    mfrc522.PCD_StopCrypto1();
    mfrc522.PICC_HaltA();
    resetPCD();
    Serial.print(F("\n>>> Mode: "));
    if (currentMode==MODE_DETECT) Serial.println(F("DETECT"));
    else if (currentMode==MODE_READ) Serial.println(F("READ"));
    else Serial.println(F("WRITE"));
    showMode(); delay(800); showIdle();
  }
}

// ======================== DISPLAY ========================

void updateDisplay() {
  unsigned long elapsed=millis()-cardTime;

  if (elapsed>8000) {
    // Timeout — go back to polling
    cardActive=false;
    resetPCD();
    showIdle();
    return;
  }

  // Only cycle screens in DETECT mode
  if (currentMode==MODE_DETECT) {
    byte np=(elapsed/2500)%2;
    if (np!=screenPhase) { screenPhase=np; if(np==0) showCardInfo(); else showStatus(); }
  }
  // In READ/WRITE mode, keep showing the result screen
}

// ======================== SETUP ========================

void setup() {
  Serial.begin(115200); delay(100);
  pinMode(BTN_PIN, INPUT_PULLUP);
  SPI.begin();
  mfrc522.PCD_Init();
  mfrc522.PCD_DumpVersionToSerial();
  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_max);
  memcpy_P(keyDefault.keyByte, commonKeys[0], 6);
  lcd.begin(16,2); showMode(); delay(1000); showIdle();
  Serial.println(F("\nRFID Cloner v2.2 Ready\n"));
}

// ======================== LOOP ========================

void loop() {
  checkButton();

  if (cardActive) { updateDisplay(); delay(50); return; }

  mfrc522.PCD_StopCrypto1();  // Safety: ensure clean crypto state

  byte atqa[2]; byte sz=sizeof(atqa);
  if (mfrc522.PICC_WakeupA(atqa,&sz)==MFRC522::STATUS_OK) {
    if (mfrc522.PICC_Select(&mfrc522.uid,0)==MFRC522::STATUS_OK) { processCardTypeA(atqa); return; }
  }

  byte reqB[]={0x05,0x00,0x00,0x00,0x00};
  byte atqb[20]; byte al=sizeof(atqb); byte vb=0;
  if (mfrc522.PCD_TransceiveData(reqB,sizeof(reqB),atqb,&al,&vb,0,true)==MFRC522::STATUS_OK && al>=5) {
    processCardTypeB(atqb,al); return;
  }

  delay(50);
}
