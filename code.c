#include <WiFi.h>
#include <HTTPClient.h>
#include <esp_wifi.h>

extern "C" {
#include "esp_log.h"
}

#define LED_PIN 2
#define DEAUTH_FRAME_TYPE 0x00C0  // Deauthentication frame type (Management Frame, Deauthentication)

const char* ssid = "Akash 5G";
const char* password = "Qawsed@1973";
const char* serverName = "http://192.168.1.9:5000/data";

// Packet data
String srcIP = "";
String destIP = "";
uint16_t srcPort = 0;
uint16_t destPort = 0;
uint8_t protocol = 0;
size_t packetSize = 0;
unsigned long packetCount = 0;
unsigned long lastSendTime = 0;
const unsigned long sendInterval = 10000; // 10 seconds in milliseconds

// Callback function for promiscuous mode
void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type == WIFI_PKT_MGMT) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *data = pkt->payload;
    
    // Extract the frame control field from the packet
    uint16_t frameControl = (data[0] | (data[1] << 8));
    
    // Check if the frame type is Deauthentication (0x00C0)
    if ((frameControl & 0x00FC) == DEAUTH_FRAME_TYPE) {
      Serial.println("Deauthentication packet detected!");
      // Blink LED to indicate detection
      pinMode(LED_PIN, OUTPUT);
      digitalWrite(LED_PIN, LOW); // Ensure LED is initially off
  
      digitalWrite(LED_PIN, HIGH);
      delay(100);
      digitalWrite(LED_PIN, LOW);
      delay(100);
      pinMode(LED_PIN, OUTPUT);
      digitalWrite(LED_PIN, LOW); // Ensure LED is initially off
  
      digitalWrite(LED_PIN, HIGH);
      delay(100);
      digitalWrite(LED_PIN, LOW);
      
      // Optionally, print packet details
      Serial.print("Packet Data: ");
      for (int i = 0; i < pkt->rx_ctrl.sig_len; i++) {
        if (i % 16 == 0) {
          Serial.println();
        }
        Serial.print(data[i], HEX);
        Serial.print(" ");
      }
      Serial.println();
    }
  } else if (type == WIFI_PKT_DATA) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *data = pkt->payload;
    int length = pkt->rx_ctrl.sig_len;
    
    // Check for IP packets
    if (length >= 34) {
      int ipHeaderStart = 42; // Adjusted to skip the radiotap header
      // Extract IP addresses
      srcIP = String(data[ipHeaderStart + 12]) + "." +
              String(data[ipHeaderStart + 13]) + "." +
              String(data[ipHeaderStart + 14]) + "." +
              String(data[ipHeaderStart + 15]);
      destIP = String(data[ipHeaderStart + 16]) + "." +
               String(data[ipHeaderStart + 17]) + "." +
               String(data[ipHeaderStart + 18]) + "." +
               String(data[ipHeaderStart + 19]);
      
      // Check if the packet is not from or to this device
      if (srcIP != WiFi.localIP().toString() && destIP != WiFi.localIP().toString()) {
        // Extract protocol (TCP = 6, UDP = 17)
        protocol = data[ipHeaderStart + 9];
        // Extract ports (if TCP or UDP)
        if (protocol == 6 || protocol == 17) {
          srcPort = (data[ipHeaderStart + 20] << 8) | data[ipHeaderStart + 21];
          destPort = (data[ipHeaderStart + 22] << 8) | data[ipHeaderStart + 23];
        }
        packetSize = length;
        packetCount++;
      }
    }
  }
}

void setup() {
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW); // Ensure LED is initially off
  
  Serial.begin(115200);
  
  // Test LED
  digitalWrite(LED_PIN, HIGH);
  delay(1000);
  digitalWrite(LED_PIN, LOW);
  delay(1000);
  
  Serial.println("LED test complete. Starting WiFi setup...");
  
  // Initialize WiFi
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  Serial.println("Connecting to WiFi...");
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting...");
  }
  Serial.println("Connected to WiFi");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
  
  // Initialize ESP-IDF WiFi functions
  if (esp_wifi_set_promiscuous(true) == ESP_OK) {
    Serial.println("Promiscuous mode enabled");
  } else {
    Serial.println("Failed to enable promiscuous mode");
  }
  esp_wifi_set_promiscuous_rx_cb(promiscuousCallback); // Set the callback function
  
  // Set WiFi channel (you may need to adjust this)
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  
  Serial.println("Listening for packets...");
}

void loop() {
  unsigned long currentTime = millis();
  
  if (currentTime - lastSendTime >= sendInterval) {
    if (WiFi.status() == WL_CONNECTED) {
      HTTPClient http;
      http.begin(serverName);
      http.addHeader("Content-Type", "application/json");
      String jsonData = "{\"packet_count\":" + String(packetCount) + 
                         ", \"last_source_ip\":\"" + srcIP + 
                         "\", \"last_destination_ip\":\"" + destIP + 
                         "\", \"last_source_port\":" + String(srcPort) +
                         ", \"last_destination_port\":" + String(destPort) +
                         ", \"last_protocol\":" + String(protocol) +
                         ", \"last_packet_size\":" + String(packetSize) + "}";
                         
      int httpResponseCode = http.POST(jsonData);
      if (httpResponseCode > 0) {
        String response = http.getString();
        Serial.println("HTTP Response Code: " + String(httpResponseCode));
        Serial.println("Response: " + response);
      } else {
        Serial.println("Error on HTTP request");
      }
      http.end();
      
      // Reset packet count after sending
      packetCount = 0;
    }
    lastSendTime = currentTime;
  }
}
