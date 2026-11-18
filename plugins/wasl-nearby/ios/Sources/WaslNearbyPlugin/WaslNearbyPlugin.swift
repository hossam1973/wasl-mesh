import Foundation
import UIKit
import Capacitor
import MultipeerConnectivity

/// Phone-to-phone mesh links with Apple Multipeer Connectivity
/// (Bluetooth + peer-to-peer Wi-Fi, no internet, no access point).
/// Trust is handled by the web layer: signed identity cards and end-to-end encryption.
@objc(WaslNearbyPlugin)
public class WaslNearbyPlugin: CAPPlugin, CAPBridgedPlugin, MCSessionDelegate, MCNearbyServiceAdvertiserDelegate, MCNearbyServiceBrowserDelegate {
    public let identifier = "WaslNearbyPlugin"
    public let jsName = "WaslNearby"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "start", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "send", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "stop", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "ipStart", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "ipConnect", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "kissConnect", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "kissSend", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "kissClose", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "saveFile", returnType: CAPPluginReturnPromise)
    ]

    private let serviceType = "wasl-mesh"          // must match NSBonjourServices in Info.plist
    private var me: MCPeerID?
    private var session: MCSession?
    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?
    private var peers: [String: MCPeerID] = [:]
    private var inRange: [String: MCPeerID] = [:]          // found by the browser and not lost
    private var tries: [String: Int] = [:]

    private func invite(_ peerID: MCPeerID) {
        guard let me = me, let s = session, let br = browser, me.displayName < peerID.displayName else { return }
        br.invitePeer(peerID, to: s, withContext: nil, timeout: 20)
    }
    private let lock = NSLock()
    private lazy var ip: WaslIpMesh = {
        let m = WaslIpMesh()
        m.onConnected = { [weak self] id in self?.notifyListeners("connected", data: ["id": id]) }
        m.onData = { [weak self] id, d in self?.notifyListeners("data", data: ["id": id, "data": d.base64EncodedString()]) }
        m.onDisconnected = { [weak self] id in self?.notifyListeners("disconnected", data: ["id": id]) }
        m.onKissData = { [weak self] id, d in self?.notifyListeners("kissData", data: ["id": id, "data": d.base64EncodedString()]) }
        m.onKissClosed = { [weak self] id in self?.notifyListeners("kissClosed", data: ["id": id]) }
        m.onError = { [weak self] w, msg in self?.notifyListeners("error", data: ["where": w, "message": msg]) }
        return m
    }()

    /// IP mesh: Wi-Fi without internet, Ethernet, microwave links, AREDN.
    @objc func ipStart(_ call: CAPPluginCall) {
        let name = String((call.getString("name") ?? "wasl").prefix(60))
        ip.start(name: name) { port, err in
            if let port = port { call.resolve(["port": Int(port), "addresses": WaslIpMesh.localAddresses()]) }
            else { call.reject("ip_start_failed", nil, err) }
        }
    }

    @objc func ipConnect(_ call: CAPPluginCall) {
        guard let host = call.getString("host"), let port = call.getInt("port") else { call.reject("bad_args"); return }
        ip.dial(host: host, port: UInt16(clamping: port)); call.resolve()
    }

    @objc func kissConnect(_ call: CAPPluginCall) {
        guard let host = call.getString("host"), let port = call.getInt("port") else { call.reject("bad_args"); return }
        ip.kissConnect(host: host, port: UInt16(clamping: port)) { id, err in
            if let id = id { call.resolve(["id": id]) } else { call.reject("modem_unreachable: \(err ?? "")") }
        }
    }

    @objc func kissSend(_ call: CAPPluginCall) {
        guard let id = call.getString("id"), let b64 = call.getString("data"), let d = Data(base64Encoded: b64) else { call.reject("bad_args"); return }
        ip.kissSend(id: id, data: d) { ok in ok ? call.resolve() : call.reject("send_failed") }
    }

    @objc func kissClose(_ call: CAPPluginCall) {
        if let id = call.getString("id") { ip.kissClose(id: id) }
        call.resolve()
    }

    /// Hand a bundle file to the share sheet (save to Files, AirDrop, USB drive...).
    @objc func saveFile(_ call: CAPPluginCall) {
        guard let name = call.getString("name"), let b64 = call.getString("data"), let data = Data(base64Encoded: b64) else { call.reject("bad_args"); return }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        do { try data.write(to: url) } catch { call.reject("write_failed", nil, error); return }
        DispatchQueue.main.async {
            guard let vc = self.bridge?.viewController else { call.reject("no_view"); return }
            let av = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            av.popoverPresentationController?.sourceView = vc.view
            vc.present(av, animated: true) { call.resolve(["path": name]) }
        }
    }

    private func key(_ p: MCPeerID) -> String { return "\(p.displayName)#\(p.hash)" }

    @objc func start(_ call: CAPPluginCall) {
        let name = String((call.getString("name") ?? "wasl").prefix(60))
        DispatchQueue.main.async {
            if self.session != nil { call.resolve(); return }
            let me = MCPeerID(displayName: name)
            let session = MCSession(peer: me, securityIdentity: nil, encryptionPreference: .required)
            session.delegate = self
            let adv = MCNearbyServiceAdvertiser(peer: me, discoveryInfo: nil, serviceType: self.serviceType)
            adv.delegate = self
            let br = MCNearbyServiceBrowser(peer: me, serviceType: self.serviceType)
            br.delegate = self
            self.me = me; self.session = session; self.advertiser = adv; self.browser = br
            adv.startAdvertisingPeer()
            br.startBrowsingForPeers()
            call.resolve()
        }
    }

    @objc func send(_ call: CAPPluginCall) {
        guard let id = call.getString("id"), let b64 = call.getString("data"), let data = Data(base64Encoded: b64) else {
            call.reject("bad_args"); return
        }
        if id.hasPrefix("ip:") { ip.send(id: id, data: data) { ok in ok ? call.resolve() : call.reject("send_failed") }; return }
        lock.lock(); let peer = peers[id]; lock.unlock()
        guard let p = peer, let s = session else { call.reject("not_connected"); return }
        do { try s.send(data, toPeers: [p], with: .reliable); call.resolve() }
        catch { call.reject("send_failed", nil, error) }
    }

    @objc func stop(_ call: CAPPluginCall) {
        DispatchQueue.main.async {
            self.advertiser?.stopAdvertisingPeer(); self.browser?.stopBrowsingForPeers(); self.session?.disconnect(); self.ip.stop()
            self.advertiser = nil; self.browser = nil; self.session = nil
            self.lock.lock(); self.peers.removeAll(); self.lock.unlock()
            call.resolve()
        }
    }

    // MARK: browser / advertiser
    public func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String: String]?) {
        notifyListeners("found", data: ["id": key(peerID), "name": peerID.displayName])
        inRange[key(peerID)] = peerID; tries[key(peerID)] = 0
        invite(peerID)            // only the lexically smaller name invites, to avoid collisions
    }
    public func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        inRange.removeValue(forKey: key(peerID)); tries.removeValue(forKey: key(peerID))
        notifyListeners("lost", data: ["id": key(peerID)])
    }
    public func browser(_ browser: MCNearbyServiceBrowser, didNotStartBrowsingForPeers error: Error) {
        notifyListeners("error", data: ["where": "browse", "message": error.localizedDescription])
    }
    public func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID,
                           withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        invitationHandler(true, session)
    }
    public func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didNotStartAdvertisingPeer error: Error) {
        notifyListeners("error", data: ["where": "advertise", "message": error.localizedDescription])
    }

    // MARK: session
    public func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        let k = key(peerID)
        switch state {
        case .connected:
            lock.lock(); peers[k] = peerID; lock.unlock()
            notifyListeners("connected", data: ["id": k])
        case .notConnected:
            lock.lock(); let had = peers.removeValue(forKey: k) != nil; lock.unlock()
            if had { notifyListeners("disconnected", data: ["id": k]) }
            // failed invite or dropped link: retry with backoff while the peer is still in range
            DispatchQueue.main.async {
                guard let p = self.inRange[k] else { return }
                let n = (self.tries[k] ?? 0) + 1; self.tries[k] = n
                if n <= 5 { DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(1500 * n + Int.random(in: 0...1000))) { self.invite(p) } }
            }
        default: break
        }
    }
    public func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        notifyListeners("data", data: ["id": key(peerID), "data": data.base64EncodedString()])
    }
    public func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) { }
    public func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) { }
    public func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) { }
}
