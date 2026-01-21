import SwiftUI

let SERVER_URL = "http://0.0.0.0:0000/api/heartbeat"
let API_TOKEN = ""

struct ContentView: View {
    @State private var status = "Initializing..."
    let timer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()
    
    var body: some View {
        VStack {
            Image(systemName: "lock.shield.fill")
                .resizable()
                .frame(width: 100, height: 120)
                .foregroundColor(.green)
            Text("Aegis iOS Client")
                .font(.largeTitle)
                .padding()
            Text(status)
                .foregroundColor(.gray)
        }
        .onReceive(timer) { _ in sendHeartbeat() }
    }
    
    func sendHeartbeat() {
        guard let url = URL(string: SERVER_URL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body: [String: Any] = [
            "token": API_TOKEN,
            "hostname": UIDevice.current.name,
            "device_type": "ios",
            "os_version": UIDevice.current.systemVersion,
            "battery": Int(UIDevice.current.batteryLevel * 100)
        ]
        
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        
        URLSession.shared.dataTask(with: request) { _, response, error in
            DispatchQueue.main.async {
                if error != nil { self.status = "Disconnected" }
                else if let http = response as? HTTPURLResponse, http.statusCode == 200 { self.status = "Connected: Secure" }
                else { self.status = "Authentication Error" }
            }
        }.resume()
    }
}