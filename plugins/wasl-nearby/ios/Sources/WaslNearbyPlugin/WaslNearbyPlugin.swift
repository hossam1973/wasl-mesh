import Foundation
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
        CAPPluginMethod(name: "stop", returnType: CAPPluginReturnPromise)
    ]

    private let serviceType = "wasl-mesh"          // must match NSBonjourServices in Info.plist
    private var me: MCPeerID?
    private var session: MCSession?
    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?
    private var peers: [String: MCPeerID] = [:]
    private let lock = NSLock()

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
        lock.lock(); let peer = peers[id]; lock.unlock()
        guard let p = peer, let s = session else { call.reject("not_connected"); return }
        do { try s.send(data, toPeers: [p], with: .reliable); call.resolve() }
        catch { call.reject("send_failed", nil, error) }
    }

    @objc func stop(_ call: CAPPluginCall) {
        DispatchQueue.main.async {
            self.advertiser?.stopAdvertisingPeer(); self.browser?.stopBrowsingForPeers(); self.session?.disconnect()
            self.advertiser = nil; self.browser = nil; self.session = nil
            self.lock.lock(); self.peers.removeAll(); self.lock.unlock()
            call.resolve()
        }
    }

    // MARK: browser / advertiser
    public func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String: String]?) {
        notifyListeners("found", data: ["id": key(peerID), "name": peerID.displayName])
        // only one side invites, to avoid simultaneous-invite collisions
        guard let me = me, let s = session, me.displayName < peerID.displayName else { return }
        browser.invitePeer(peerID, to: s, withContext: nil, timeout: 20)
    }
    public func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
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
