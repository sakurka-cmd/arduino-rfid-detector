/**
 * RFID Card Cloner v3.7 Direct
 * 
 * Write block 0 IMMEDIATELY after initial card select.
 * No reSelect, no antenna toggle between attempts.
 * Card is freshly selected when writeMifareClassic is called.
 * Try: Std Write A, Std Write B, change trailer then write.
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
  lcd.clear(); lcd.setCursor(0,0); lcd.print(cardTypeStr);
  lcd.setCursor(0,1); lcd.print(F("UID:"));
  byte start = (lastUidLen<=4) ? 0 : lastUidLen-5;
  for (byte i=start; i<lastUidLen && i<start+5; i++) {
    if (lastUid[i]<0x10) lcd.print('0');
    lcd.print(lastUid[i], HEX);
  }
}

void showAtqa() {
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("ATQA:"));
  if (lastAtqa[1]<0x10) lcd.print('0'); lcd.print(lastAtqa[1], HEX); lcd.print(' ');
  if (lastAtqa[0]<0x10) lcd.print('0'); lcd.print(lastAtqa[0], HEX);
  lcd.setCursor(0,1); lcd.print(F("SAK:"));
  if (lastSak<0x10) lcd.print('0'); lcd.print(lastSak, HEX);
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
  Serial.print(F(" ATQA:")); Serial.print(lastAtqa[1], HEX); Serial.print(lastAtqa[0], HEX);
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
      Serial.print(F("  Auth ")); 
      if(cmd==MFRC522::PICC_CMD_MF_AUTH_KEY_B) Serial.print(F("KB#"));
      else Serial.print(F("KA#"));
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

byte getSectorCount() {
  if (lastSak==0x09) return 5;
  return 16;
}

bool readMifareClassic() {
  dumpSectorsCount = getSectorCount();
  MFRC522::MIFARE_Key akey;
  Serial.println(F("\n--- Read ---"));

  for (byte s=0; s<dumpSectorsCount; s++) {
    lcd.clear(); lcd.setCursor(0,0);
    lcd.print(F("Reading")); lcd.print(s+1); lcd.print(F("/")); lcd.print(dumpSectorsCount);
    if (!authSector(s, &akey)) { sectorStatus[s]=2; continue; }
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

bool writeMifareClassic() {
  if (!dumpReady) {
    showResult(F("No dump!"),F("READ first"));
    resetPCD(); return false;
  }

  Serial.println(F("\n--- Write v3.7 Direct ---"));
  Serial.print(F("  Target UID: "));
  for (byte i=0; i<mfrc522.uid.size; i++) {
    if (mfrc522.uid.uidByte[i]<0x10) Serial.print('0');
    Serial.print(mfrc522.uid.uidByte[i], HEX); Serial.print(' ');
  }
  Serial.println();

  // Build block 0 with source UID
  byte newBlock0[BS];
  newBlock0[0] = sourceUid[0]; newBlock0[1] = sourceUid[1];
  newBlock0[2] = sourceUid[2]; newBlock0[3] = sourceUid[3];
  newBlock0[4] = sourceUid[0] ^ sourceUid[1] ^ sourceUid[2] ^ sourceUid[3];
  for (byte i=5; i<BS; i++) newBlock0[i] = cardDump[0][0][i];

  Serial.print(F("  Data:"));
  for (byte i=0;i<BS;i++) { Serial.print(' '); if(newBlock0[i]<0x10)Serial.print('0'); Serial.print(newBlock0[i],HEX); }
  Serial.println();

  // Card is ALREADY selected (from processCardTypeA WUPA+Select)
  // Try auth + write IMMEDIATELY without any reSelect

  MFRC522::MIFARE_Key akey;

  // === Try 1: Auth any key, write block 0 ===
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("Auth+Write..."));
  lcd.setCursor(0,1);
  lcd.print(F("Try 1"));
  delay(800);

  Serial.println(F("  --- T1: Auth any + MIFARE_Write B0 ---"));

  if (authSector(0, &akey)) {
    MFRC522::StatusCode st = mfrc522.MIFARE_Write(0, newBlock0, BS);
    Serial.print(F("  Write result: ")); Serial.println((int)st);
    if (st == MFRC522::STATUS_OK) {
      showResult(F("CLONE OK!"), F("T1 success"));
      Serial.println(F("  *** WRITE SUCCESS ***"));
      mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
      return true;
    }
    // NAK = 255, TIMEOUT = 3, ERROR = 2
    lcd.clear(); lcd.setCursor(0,0);
    lcd.print(F("T1 err:")); lcd.print((int)st);
    lcd.setCursor(0,1);
    if (st==255) lcd.print(F("NAK!"));
    else if (st==3) lcd.print(F("TIMEOUT"));
    else lcd.print(F("ERROR"));
    Serial.print(F("  NAK - card refuses block 0 write"));
    delay(1500);
  } else {
    Serial.println(F("  Auth FAIL - unknown key"));
    lcd.clear(); lcd.setCursor(0,0); lcd.print(F("Auth FAIL!"));
    delay(1500);
  }

  // === Try 2: Read current block 3, change access bits, write trailer, then write B0 ===
  Serial.println(F("  --- T2: Change trailer access bits ---"));
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("Try 2: change"));
  lcd.setCursor(0,1);
  lcd.print(F("access bits"));
  delay(800);

  // Re-auth (card should still be selected)
  if (authSector(0, &akey)) {
    // Read current trailer
    byte trailer[BS];
    byte buf[BS+2]; byte sz2=sizeof(buf);
    if (mfrc522.MIFARE_Read(3, buf, &sz2)==MFRC522::STATUS_OK) {
      memcpy(trailer, buf, BS);

      Serial.print(F("  Current B3:"));
      for (byte i=0;i<BS;i++){Serial.print(' ');if(trailer[i]<0x10)Serial.print('0');Serial.print(trailer[i],HEX);}
      Serial.println();

      // Write trailer with ALL blocks writable by Key A
      // Access bits: FF 0F 78 = all blocks read/write with Key A
      byte newTrailer[BS];
      // Keep Key A as FF FF FF FF FF FF
      newTrailer[0]=0xFF; newTrailer[1]=0xFF; newTrailer[2]=0xFF;
      newTrailer[3]=0xFF; newTrailer[4]=0xFF; newTrailer[5]=0xFF;
      // Access bits: FF 0F 78
      newTrailer[6]=0xFF; newTrailer[7]=0x0F; newTrailer[8]=0x78;
      newTrailer[9]=0x00; // GPB
      // Keep Key B
      memcpy(&newTrailer[10], &trailer[10], 6);

      Serial.print(F("  New B3:"));
      for (byte i=0;i<BS;i++){Serial.print(' ');if(newTrailer[i]<0x10)Serial.print('0');Serial.print(newTrailer[i],HEX);}
      Serial.println();

      mfrc522.PCD_StopCrypto1();
      if (authSector(0, &akey)) {
        MFRC522::StatusCode st3 = mfrc522.MIFARE_Write(3, newTrailer, BS);
        Serial.print(F("  Trailer write: ")); Serial.println((int)st3);

        if (st3 == MFRC522::STATUS_OK) {
          lcd.clear(); lcd.setCursor(0,0);
          lcd.print(F("Trailer OK"));
          delay(800);

          // Re-auth and write block 0
          mfrc522.PCD_StopCrypto1();
          if (authSector(0, &akey)) {
            MFRC522::StatusCode st0 = mfrc522.MIFARE_Write(0, newBlock0, BS);
            Serial.print(F("  B0 write: ")); Serial.println((int)st0);

            if (st0 == MFRC522::STATUS_OK) {
              showResult(F("CLONE OK!"), F("T2 trailer+write"));
              mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
              return true;
            }
          }
        }
      }
    }
  }

  // === Try 3: All 10 keys individually, write with each ===
  Serial.println(F("  --- T3: Try all 10 keys individually ---"));
  lcd.clear(); lcd.setCursor(0,0);
  lcd.print(F("Try 3: all"));
  lcd.setCursor(0,1);
  lcd.print(F("10 keys..."));
  delay(800);

  for (byte k=0; k<NK; k++) {
    mfrc522.PCD_StopCrypto1();
    memcpy_P(akey.keyByte, commonKeys[k], 6);
    
    // Try Key A
    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 3, &akey, &(mfrc522.uid))==MFRC522::STATUS_OK) {
      Serial.print(F("  KA#")); Serial.print(k);
      MFRC522::StatusCode st = mfrc522.MIFARE_Write(0, newBlock0, BS);
      Serial.print(F(" write=")); Serial.println((int)st);
      if (st == MFRC522::STATUS_OK) {
        lcd.clear(); lcd.setCursor(0,0);
        lcd.print(F("OK! KA#")); lcd.print(k);
        showResult(F("CLONE OK!"), F("T3 KA"));
        mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
        return true;
      }
    }
    // Try Key B
    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, 3, &akey, &(mfrc522.uid))==MFRC522::STATUS_OK) {
      Serial.print(F("  KB#")); Serial.print(k);
      MFRC522::StatusCode st = mfrc522.MIFARE_Write(0, newBlock0, BS);
      Serial.print(F(" write=")); Serial.println((int)st);
      if (st == MFRC522::STATUS_OK) {
        lcd.clear(); lcd.setCursor(0,0);
        lcd.print(F("OK! KB#")); lcd.print(k);
        showResult(F("CLONE OK!"), F("T3 KB"));
        mfrc522.PCD_StopCrypto1(); resetCard(); resetPCD();
        return true;
      }
    }
  }

  // ALL FAILED
  showResult(F("NOT WRITABLE"), F("Regular card"));
  Serial.println(F("\n*** CARD IS NOT CUID/FUID/MAGIC ***"));
  Serial.println(F("    Block 0 is factory-locked (OTP)"));
  Serial.println(F("    Need genuine CUID or PN532 programmer"));
  delay(5000);
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
  if (elapsed>20000) { cardActive=false; resetCard(); resetPCD(); showIdle(); return; }
  if (currentMode==MODE_DETECT) {
    byte np=(elapsed/3000)%3;
    if (np!=screenPhase) { screenPhase=np; if(np==0) showCardInfo(); else if(np==1) showStatus(); else showAtqa(); }
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
  Serial.println(F("\nRFID Cloner v3.7 Direct Ready\n"));
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
