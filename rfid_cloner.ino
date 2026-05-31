/**
 * RFID Card Cloner v3.2 Magic
 * 
 * After standard MIFARE_Write fails on block 0 (NAK):
 * tries Magic UID (Gen1a) backdoor write via raw TRANSCEIVE.
 * Command: 0x40 + blockNum + data[16] = 18 bytes
 * Response: 0x0A (4-bit ACK)
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

byte lastUid[10] = {0};
byte lastUidLen = 0;
byte lastSak = 0;
byte lastAtqa[2] = {0, 0};
char cardTypeStr[20] = "";
char readStatusStr[12] = "";
char cloneStatusStr[12] = "";

byte sourceUid[4] = {0};
bool hasSource = false;

bool cardActive = false;
unsigned long cardTime = 0;
byte screenPhase = 0;

#define MAX_SECTORS 16
#define BPS 4
#define BS 16

byte cardDump[MAX_SECTORS][BPS][BS];
byte sectorStatus[MAX_SECTORS];
bool dumpReady = false;
byte dumpSectorsCount = 0;

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
unsigned long lastBtnPress = 0;

void resetPCD() {
  mfrc522.PCD_Init();
  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_max);
}

void resetCard() {
  mfrc522.PCD_AntennaOff();
  delay(1);
  mfrc522.PCD_AntennaOn();
  delay(1);
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

void printHexLcd(byte b) {
  if (b < 0x10) lcd.print('0');
  lcd.print(b, HEX);
}

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
  lcd.setCursor(0,1); lcd.print(F("Apply card"));
}

void showCardInfo() {
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(cardTypeStr);
  lcd.setCursor(0,1);
  lcd.print(F("UID:"));
  byte show = (lastUidLen<=4) ? lastUidLen : 5;
  byte start = (lastUidLen<=4) ? 0 : lastUidLen-5;
  for (byte i=start; i<lastUidLen && i<start+5; i++) {
    if (lastUid[i]<0x10) lcd.print('0');
    lcd.print(lastUid[i], HEX);
  }
}

void showAtqa() {
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("ATQA:"));
  if (lastAtqa[1]<0x10) lcd.print('0');
  lcd.print(lastAtqa[1], HEX);
  lcd.print(' ');
  if (lastAtqa[0]<0x10) lcd.print('0');
  lcd.print(lastAtqa[0], HEX);
  lcd.setCursor(0,1);
  lcd.print(F("SAK:"));
  if (lastSak<0x10) lcd.print('0');
  lcd.print(lastSak, HEX);
}

void showStatus() {
  lcd.clear(); lcd.setCursor(0,0); lcd.print(readStatusStr);
  lcd.setCursor(0,1); lcd.print(cloneStatusStr);
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

void printCardInfo() {
  Serial.print(F("Card: "));
  for (byte i=0; i<lastUidLen; i++) {
    if (lastUid[i]<0x10) Serial.print('0');
    Serial.print(lastUid[i], HEX);
    if (i<lastUidLen-1) Serial.print(' ');
  }
  Serial.print(F(" ATQA:"));
  Serial.print(lastAtqa[1], HEX); Serial.print(lastAtqa[0], HEX);
  Serial.print(F(" SAK:")); Serial.print(lastSak, HEX);
  Serial.print(F(" ")); Serial.println(cardTypeStr);
}

void printFullDump() {
  Serial.println(F("\n=== Dump ==="));
  for (byte s=0; s<dumpSectorsCount; s++) {
    if (sectorStatus[s]==2) { Serial.print(F("  S")); Serial.print(s); Serial.println(F(": AUTH FAIL")); continue; }
    if (sectorStatus[s]!=1) continue;
    for (byte b=0; b<BPS; b++) {
      byte bn=s*BPS+b;
      Serial.print(F("  B")); if(bn<10)Serial.print(' ');
      Serial.print(bn); Serial.print(F(": "));
      for (byte j=0; j<BS; j++) {
        if (cardDump[s][b][j]<0x10) Serial.print('0');
        Serial.print(cardDump[s][b][j], HEX); Serial.print(' ');
      }
      Serial.println();
    }
  }
  Serial.println(F("==========\n"));
}

bool authKey(byte sector, MFRC522::MIFARE_Key *keyOut, byte cmd) {
  mfrc522.PCD_StopCrypto1();
  byte trailerBlock = sector*BPS+3;
  for (byte k=0; k<NK; k++) {
    memcpy_P(keyOut->keyByte, commonKeys[k], 6);
    if (mfrc522.PCD_Authenticate(cmd, trailerBlock, keyOut, &(mfrc522.uid))==MFRC522::STATUS_OK) {
      Serial.print(F("  S")); Serial.print(sector);
      if(cmd==MFRC522::PICC_CMD_MF_AUTH_KEY_B) Serial.print(F(" KB#"));
      else Serial.print(F(" KA#"));
      Serial.println(k);
      return true;
    }
  }
  return false;
}

bool authSector(byte sector, MFRC522::MIFARE_Key *keyOut) {
  if (authKey(sector, keyOut, MFRC522::PICC_CMD_MF_AUTH_KEY_A)) return true;
  return authKey(sector, keyOut, MFRC522::PICC_CMD_MF_AUTH_KEY_B);
}

bool authKeyB(byte sector, MFRC522::MIFARE_Key *keyOut) {
  return authKey(sector, keyOut, MFRC522::PICC_CMD_MF_AUTH_KEY_B);
}

byte getSectorCount() {
  if (lastSak==0x09) return 5;
  if (lastSak==0x18) return 16;
  return 16;
}

bool readMifareClassic() {
  dumpSectorsCount = getSectorCount();
  MFRC522::MIFARE_Key authKey;
  Serial.println(F("\n--- Read ---"));

  for (byte s=0; s<dumpSectorsCount; s++) {
    lcd.clear(); lcd.setCursor(0,0);
    lcd.print(F("Reading")); lcd.print(s+1); lcd.print(F("/")); lcd.print(dumpSectorsCount);
    if (!authSector(s, &authKey)) { sectorStatus[s]=2; continue; }
    bool ok=true;
    for (byte b=0; b<BPS; b++) {
      byte bn=s*BPS+b;
      byte buf[BS+2]; byte sz2=sizeof(buf);
      if (mfrc522.MIFARE_Read(bn,buf,&sz2)==MFRC522::STATUS_OK)
        memcpy(cardDump[s][b],buf,BS);
      else ok=false;
    }
    sectorStatus[s]=ok?1:3;
  }

  byte okCnt=0;
  for (byte s=0; s<dumpSectorsCount; s++) if(sectorStatus[s]==1) okCnt++;
  dumpReady=(okCnt>0);

  if (sectorStatus[0]==1) {
    memcpy(sourceUid, cardDump[0][0], 4);
    hasSource = true;
    Serial.print(F("Source: "));
    for (byte i=0;i<4;i++) { if(sourceUid[i]<0x10) Serial.print('0'); Serial.print(sourceUid[i],HEX); Serial.print(' '); }
    Serial.println();
  }

  mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
  printFullDump();
  return dumpReady;
}

// Build source UID block 0 data for writing to CUID/Magic card
void buildBlock0(byte *out) {
  out[0] = sourceUid[0];
  out[1] = sourceUid[1];
  out[2] = sourceUid[2];
  out[3] = sourceUid[3];
  out[4] = sourceUid[0] ^ sourceUid[1] ^ sourceUid[2] ^ sourceUid[3]; // BCC
  // Copy rest from original block 0 (SAK, ATQA, etc)
  for (byte i=5; i<BS; i++) out[i] = cardDump[0][0][i];
}

bool writeMifareClassic() {
  if (!dumpReady) {
    showResult(F("No dump!"),F("READ first"));
    resetPCD();
    return false;
  }

  Serial.println(F("\n--- Write v3.2 Magic ---"));
  Serial.print(F("  Target UID: "));
  for (byte i=0; i<mfrc522.uid.size; i++) {
    if (mfrc522.uid.uidByte[i]<0x10) Serial.print('0');
    Serial.print(mfrc522.uid.uidByte[i], HEX);
    Serial.print(' ');
  }
  Serial.println();

  // ===== Prepare block 0 data with source UID =====
  byte newBlock0[BS];
  buildBlock0(newBlock0);
  Serial.print(F("  Write data: "));
  for (byte i=0; i<BS; i++) { if(newBlock0[i]<0x10) Serial.print('0'); Serial.print(newBlock0[i],HEX); Serial.print(' '); }
  Serial.println();

  // ===== Step 1: Auth sector 0 =====
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("Target:"));
  for (byte i=0; i<4 && i<mfrc522.uid.size; i++) printHexLcd(mfrc522.uid.uidByte[i]);
  lcd.setCursor(0,1);
  lcd.print(F("Auth S0..."));
  delay(1500);

  MFRC522::MIFARE_Key authKey;
  if (!authSector(0, &authKey)) {
    showResult(F("Auth FAIL"),F("Unknown key"));
    Serial.println(F("  S0 AUTH FAIL"));
    delay(3000);
    resetCard(); resetPCD();
    return false;
  }

  lcd.setCursor(0,1);
  lcd.print(F("Auth OK"));
  Serial.println(F("  Auth OK"));
  delay(1000);

  // ===== Step 2: Try standard MIFARE_Write on block 0 =====
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("Std write B0..."));
  delay(1000);

  MFRC522::StatusCode st = mfrc522.MIFARE_Write(0, newBlock0, BS);
  if (st == MFRC522::STATUS_OK) {
    // Genuine CUID - standard write works!
    lcd.clear(); lcd.setCursor(0,0);
    lcd.print(F("Std write OK!"));
    lcd.setCursor(0,1);
    lcd.print(F("Genuine CUID"));
    Serial.println(F("  Standard write OK - genuine CUID!"));
    delay(2000);

    // Write blocks 1-2 normally
    for (byte b=1; b<=2; b++) {
      mfrc522.PCD_StopCrypto1();
      if (!authSector(0, &authKey)) break;
      st = mfrc522.MIFARE_Write(b, cardDump[0][b], BS);
      Serial.print(F("  B")); Serial.print(b);
      Serial.println(st==MFRC522::STATUS_OK ? F(" OK") : F(" FAIL"));
    }

    showResult(F("CLONE OK!"), F("Std method"));
    Serial.println(F("*** CLONE SUCCESS (standard) ***"));
    mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
    return true;
  }

  // Standard write failed - try magic
  Serial.print(F("  Std write fail: ")); Serial.println((int)st);
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("Std fail:")); lcd.print((int)st);
  lcd.setCursor(0,1);
  lcd.print(F("Try magic..."));
  delay(2000);

  // ===== Step 3: Magic UID (Gen1a) write via TRANSCEIVE =====
  // Command format: 0x40 + blockNum + data[16] = 18 bytes
  // Must be sent while crypto1 is active (after auth)
  // Response: 0x0A (4-bit ACK)

  Serial.println(F("  Magic write via TRANSCEIVE..."));

  // Re-authenticate for clean state
  mfrc522.PCD_StopCrypto1();
  if (!authSector(0, &authKey)) {
    showResult(F("Re-auth FAIL"),F(""));
    delay(2000);
    resetCard(); resetPCD();
    return false;
  }

  // Build magic command: 0x40 + block(0x00) + data(16 bytes) = 18 bytes
  byte magicCmd[18];
  magicCmd[0] = 0x40;  // Magic write command
  magicCmd[1] = 0x00;  // Block 0
  memcpy(&magicCmd[2], newBlock0, 16);

  Serial.print(F("  Magic cmd: "));
  for (byte i=0; i<18; i++) { if(magicCmd[i]<0x10) Serial.print('0'); Serial.print(magicCmd[i],HEX); Serial.print(' '); }
  Serial.println();

  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("Magic: 0x40 B0"));
  lcd.setCursor(0,1);
  lcd.print(F("18 bytes..."));
  delay(1500);

  byte magicResp[4] = {0};
  byte magicRespLen = sizeof(magicResp);
  byte validBits = 0;

  st = mfrc522.PCD_TransceiveData(
    magicCmd, 18, magicResp, &magicRespLen, &validBits, 0, true);

  Serial.print(F("  Magic status: ")); Serial.println((int)st);
  Serial.print(F("  Magic respLen: ")); Serial.println(magicRespLen);
  if (magicRespLen > 0) {
    Serial.print(F("  Magic resp: "));
    for (byte i=0; i<magicRespLen; i++) { if(magicResp[i]<0x10) Serial.print('0'); Serial.print(magicResp[i],HEX); Serial.print(' '); }
    Serial.println();
  }
  Serial.print(F("  ValidBits: ")); Serial.println(validBits);

  // Check response: ACK is 0x0A (4 bits, so validBits should be 4)
  if (st == MFRC522::STATUS_OK && magicRespLen > 0 && magicResp[0] == 0x0A) {
    lcd.clear(); lcd.setCursor(0,0);
    lcd.print(F("MAGIC OK!"));
    lcd.setCursor(0,1);
    lcd.print(F("ACK:0A received"));
    Serial.println(F("  *** MAGIC WRITE SUCCESS! Card is Magic UID (Gen1a) ***"));
    delay(3000);

    // Verify: re-select and read block 0
    mfrc522.PCD_StopCrypto1();
    resetCard();
    delay(5);
    resetPCD();
    delay(5);

    byte atqa[2]; byte sz=sizeof(atqa);
    if (mfrc522.PICC_WakeupA(atqa,&sz)==MFRC522::STATUS_OK &&
        mfrc522.PICC_Select(&mfrc522.uid,0)==MFRC522::STATUS_OK) {
      
      MFRC522::MIFARE_Key vKey;
      if (authSector(0, &vKey)) {
        byte vBuf[BS+2]; byte vSz=sizeof(vBuf);
        if (mfrc522.MIFARE_Read(0, vBuf, &vSz)==MFRC522::STATUS_OK) {
          lcd.clear(); lcd.setCursor(0,0);
          lcd.print(F("Verify B0:"));
          for (byte i=0; i<6; i++) printHexLcd(vBuf[i]);
          lcd.setCursor(0,1);
          lcd.print(F("UID copied!"));
          Serial.print(F("  Verify B0: "));
          for (byte i=0;i<BS;i++) { if(vBuf[i]<0x10) Serial.print('0'); Serial.print(vBuf[i],HEX); Serial.print(' '); }
          Serial.println();
          delay(4000);
        }
      }
    }

    // Now write blocks 1-2 with standard method
    mfrc522.PCD_StopCrypto1();
    resetCard(); resetPCD();

    // Re-select card
    byte atqa2[2]; byte sz2=sizeof(atqa2);
    if (mfrc522.PICC_WakeupA(atqa2,&sz2)==MFRC522::STATUS_OK &&
        mfrc522.PICC_Select(&mfrc522.uid,0)==MFRC522::STATUS_OK) {
      
      for (byte b=1; b<=2; b++) {
        mfrc522.PCD_StopCrypto1();
        if (!authSector(0, &authKey)) break;
        lcd.clear(); lcd.setCursor(0,0);
        lcd.print(F("Write B")); lcd.print(b);
        st = mfrc522.MIFARE_Write(b, cardDump[0][b], BS);
        lcd.setCursor(0,1);
        if (st==MFRC522::STATUS_OK) {
          lcd.print(F("OK"));
          Serial.print(F("  B")); Serial.print(b); Serial.println(F(" OK"));
        } else {
          lcd.print(F("ERR:")); lcd.print((int)st);
          Serial.print(F("  B")); Serial.print(b); Serial.print(F(" ERR:")); Serial.println((int)st);
        }
        delay(1000);
      }
    }

    showResult(F("CLONE OK!"), F("Magic UID!"));
    Serial.println(F("*** FULL CLONE SUCCESS (Magic UID method) ***"));
    mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
    return true;
  }

  // Magic write also failed
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("Magic fail"));
  lcd.setCursor(0,1);
  if (st==3) lcd.print(F("TIMEOUT"));
  else if (magicRespLen>0) {
    lcd.print(F("resp:"));
    printHexLcd(magicResp[0]);
    if (magicRespLen>1) printHexLcd(magicResp[1]);
  } else {
    lcd.print(F("st:")); lcd.print((int)st);
  }

  Serial.print(F("  Magic write FAILED. st=")); Serial.print((int)st);
  Serial.print(F(" respLen=")); Serial.print(magicRespLen);
  Serial.print(F(" validBits=")); Serial.println(validBits);
  delay(3000);

  // ===== Step 4: Try alternative magic - 0x43 first =====
  Serial.println(F("  Try alt magic (0x43 prefix)..."));
  
  mfrc522.PCD_StopCrypto1();
  resetCard(); delay(5); resetPCD(); delay(5);
  
  byte atqa3[2]; byte sz3=sizeof(atqa3);
  if (mfrc522.PICC_WakeupA(atqa3,&sz3)==MFRC522::STATUS_OK &&
      mfrc522.PICC_Select(&mfrc522.uid,0)==MFRC522::STATUS_OK) {
    
    if (authSector(0, &authKey)) {
      // Try 0x43 command first (some Magic UID variants)
      byte cmd43[] = {0x43, 0x00};
      byte resp43[4] = {0};
      byte resp43Len = sizeof(resp43);
      byte vb43 = 0;

      lcd.clear(); lcd.setCursor(0,0);
      lcd.print(F("Try 0x43..."));
      delay(1500);

      st = mfrc522.PCD_TransceiveData(cmd43, 2, resp43, &resp43Len, &vb43, 0, true);
      Serial.print(F("  0x43 status: ")); Serial.println((int)st);
      Serial.print(F("  0x43 respLen: ")); Serial.println(resp43Len);
      if (resp43Len > 0) {
        Serial.print(F("  0x43 resp: "));
        for (byte i=0; i<resp43Len; i++) { if(resp43[i]<0x10) Serial.print('0'); Serial.print(resp43[i],HEX); Serial.print(' '); }
        Serial.println();
      }

      // Now try 0x40 write after 0x43
      if (st == MFRC522::STATUS_OK) {
        mfrc522.PCD_StopCrypto1();
        if (authSector(0, &authKey)) {
          byte magicResp2[4] = {0};
          byte magicResp2Len = sizeof(magicResp2);
          byte vb2 = 0;

          lcd.clear(); lcd.setCursor(0,0);
          lcd.print(F("Then 0x40 B0"));
          delay(1500);

          st = mfrc522.PCD_TransceiveData(
            magicCmd, 18, magicResp2, &magicResp2Len, &vb2, 0, true);

          Serial.print(F("  0x43+0x40 status: ")); Serial.println((int)st);
          Serial.print(F("  0x43+0x40 respLen: ")); Serial.println(magicResp2Len);
          if (magicResp2Len > 0) {
            Serial.print(F("  0x43+0x40 resp: "));
            for (byte i=0; i<magicResp2Len; i++) { if(magicResp2[i]<0x10) Serial.print('0'); Serial.print(magicResp2[i],HEX); Serial.print(' '); }
            Serial.println();
          }

          if (st == MFRC522::STATUS_OK && magicResp2Len > 0 && magicResp2[0] == 0x0A) {
            lcd.clear(); lcd.setCursor(0,0);
            lcd.print(F("ALT MAGIC OK!"));
            lcd.setCursor(0,1);
            lcd.print(F("0x43+0x40"));
            Serial.println(F("  *** ALT MAGIC SUCCESS (0x43 + 0x40) ***"));
            delay(3000);

            // Verify
            mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
            byte atqa4[2]; byte sz4=sizeof(atqa4);
            if (mfrc522.PICC_WakeupA(atqa4,&sz4)==MFRC522::STATUS_OK &&
                mfrc522.PICC_Select(&mfrc522.uid,0)==MFRC522::STATUS_OK) {
              MFRC522::MIFARE_Key vk;
              if (authSector(0, &vk)) {
                byte vb[BS+2]; byte vsz=sizeof(vb);
                if (mfrc522.MIFARE_Read(0, vb, &vsz)==MFRC522::STATUS_OK) {
                  lcd.clear(); lcd.setCursor(0,0);
                  lcd.print(F("B0 now:"));
                  for (byte i=0; i<6; i++) printHexLcd(vb[i]);
                  lcd.setCursor(0,1);
                  lcd.print(F("CLONE OK!"));
                  delay(4000);
                }
              }
              // Write B1-B2
              mfrc522.PCD_StopCrypto1();
              if (authSector(0, &authKey)) {
                mfrc522.MIFARE_Write(1, cardDump[0][1], BS);
                mfrc522.PCD_StopCrypto1();
                if (authSector(0, &authKey)) mfrc522.MIFARE_Write(2, cardDump[0][2], BS);
              }
            }

            showResult(F("CLONE OK!"), F("Alt magic!"));
            mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
            return true;
          }
        }
      }

      lcd.clear(); lcd.setCursor(0,0);
      lcd.print(F("Alt magic fail"));
      lcd.setCursor(0,1);
      lcd.print(F("Not writable"));
      delay(3000);
    }
  }

  showResult(F("CLONE FAIL"), F("Not CUID/MUID"));
  Serial.println(F("\n*** ALL METHODS FAILED - CARD IS NOT WRITABLE ***"));
  Serial.println(F("    Possible: regular MIFARE, used FUID, or unsupported type"));
  mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
  return false;
}

void processCardTypeA(byte atqa[2]) {
  bool same = (lastUidLen==mfrc522.uid.size);
  if (same) { for (byte i=0;i<lastUidLen;i++) if(lastUid[i]!=mfrc522.uid.uidByte[i]) {same=false;break;} }

  if (same) {
    resetCard(); cardActive=true; cardTime=millis();
    if (currentMode==MODE_READ) showResult(F("Same card"),F("Already read"));
    else if (currentMode==MODE_WRITE) {
      if (hasSource && lastUidLen==4 && memcmp(lastUid, sourceUid, 4)==0)
        showResult(F("SOURCE card!"),F("Apply CUID!"));
      else showResult(F("Same card"),F("Remove first"));
    } else showCardInfo();
    return;
  }

  lastUidLen=mfrc522.uid.size; lastSak=mfrc522.uid.sak;
  for (byte i=0;i<lastUidLen;i++) lastUid[i]=mfrc522.uid.uidByte[i];
  lastAtqa[0]=atqa[0]; lastAtqa[1]=atqa[1];
  identifyCard(lastSak, lastAtqa[0], lastAtqa[1]);
  printCardInfo();

  if (currentMode==MODE_DETECT) {
    resetCard(); cardActive=true; cardTime=millis(); screenPhase=0; showCardInfo();
  } else if (currentMode==MODE_READ) {
    if (lastSak==0x08||lastSak==0x18||lastSak==0x09) {
      readMifareClassic();
      byte okCnt=0;
      for (byte s=0;s<dumpSectorsCount;s++) if(sectorStatus[s]==1) okCnt++;
      showReadDone(okCnt, dumpSectorsCount);
      cardActive=true; cardTime=millis();
    } else { showResult(F("Not Classic!"),F("")); resetCard(); cardActive=true; cardTime=millis(); }
  } else if (currentMode==MODE_WRITE) {
    if (lastSak==0x08) {
      writeMifareClassic();
      cardActive=true; cardTime=millis();
    } else { showResult(F("Need CUID 1K"),F("")); resetCard(); cardActive=true; cardTime=millis(); }
  }
}

void processCardTypeB(byte atqb[], byte atqbLen) {
  strcpy_P(cardTypeStr, PSTR("ISO 14443-B"));
  lastUidLen=4;
  for (byte i=0;i<4&&i+1<atqbLen;i++) lastUid[i]=atqb[1+i];
  resetCard(); cardActive=true; cardTime=millis(); screenPhase=0; showCardInfo();
}

void checkButton() {
  if (digitalRead(BTN_PIN)==LOW) {
    unsigned long now=millis();
    if (now-lastBtnPress<300) return;
    lastBtnPress=now;
    currentMode=(Mode)((currentMode+1)%3);
    cardActive=false;
    mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
    Serial.print(F("\n>>> Mode: "));
    if (currentMode==MODE_DETECT) Serial.println(F("DETECT"));
    else if (currentMode==MODE_READ) Serial.println(F("READ"));
    else {
      Serial.print(F("WRITE"));
      if (hasSource) {
        Serial.print(F(" from "));
        for (byte i=0;i<4;i++) { if(sourceUid[i]<0x10) Serial.print('0'); Serial.print(sourceUid[i],HEX); }
      }
      Serial.println();
    }
    showMode(); delay(800);
    if (currentMode==MODE_WRITE && hasSource) {
      lcd.clear(); lcd.setCursor(0,0);
      lcd.print(F("From:"));
      for (byte i=0;i<4;i++) { printHexLcd(sourceUid[i]); lcd.print(' '); }
      lcd.setCursor(0,1);
      lcd.print(F("Apply CUID!"));
      delay(2000);
    }
    showIdle();
  }
}

void updateDisplay() {
  unsigned long elapsed=millis()-cardTime;
  if (elapsed>15000) {
    cardActive=false; resetCard(); resetPCD(); showIdle();
    return;
  }
  if (currentMode==MODE_DETECT) {
    byte np=(elapsed/3000)%3;
    if (np!=screenPhase) {
      screenPhase=np;
      if(np==0) showCardInfo();
      else if(np==1) showStatus();
      else showAtqa();
    }
  }
}

void setup() {
  Serial.begin(115200); delay(100);
  pinMode(BTN_PIN, INPUT_PULLUP);
  SPI.begin();
  mfrc522.PCD_Init();
  mfrc522.PCD_DumpVersionToSerial();
  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_max);
  memcpy_P(keyDefault.keyByte, commonKeys[0], 6);
  lcd.begin(16,2); showMode(); delay(1000); showIdle();
  Serial.println(F("\nRFID Cloner v3.2 Magic Ready\n"));
}

void loop() {
  checkButton();
  if (cardActive) { updateDisplay(); delay(50); return; }
  mfrc522.PCD_StopCrypto1();
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
