import Foundation
import Network

/// Mesh links over any IP network (Wi-Fi without internet, Ethernet, microwave bridges, AREDN mesh).
/// Bonjour discovery (_waslip._tcp) on the local network; remote sites are dialled by address.
/// Frames: 4-byte big-endian length + payload. Also raw TCP streams to KISS modems (VARA, ARDOP, Direwolf).
final class WaslIpMesh {
    var onConnected: ((String) -> Void)?
    var onData: ((String, Data) -> Void)?
    var onDisconnected: ((String) -> Void)?
    var onKissData: ((String, Data) -> Void)?
    var onKissClosed: ((String) -> Void)?
    var onError: ((String, String) -> Void)?

    private let q = DispatchQueue(label: "wasl.ipmesh")
    private var listener: NWListener?
    private var browser: NWBrowser?
    private var conns: [String: NWConnection] = [:]
    private var kiss: [String: NWConnection] = [:]
    private var dialed = Set<String>()
    private var name = "wasl"
    private var port: UInt16 = 0

    func start(name: String, done: @escaping (UInt16?, Error?) -> Void) {
        q.async {
            if let l = self.listener, let p = l.port { done(p.rawValue, nil); return }
            self.name = name
            do {
                let l = try NWListener(using: .tcp, on: .any)
                l.service = NWListener.Service(name: name, type: "_waslip._tcp")
                l.newConnectionHandler = { [weak self] c in self?.attach(c) }
                var reported = false
                l.stateUpdateHandler = { st in
                    guard !reported else { return }
                    switch st {
                    case .ready: reported = true; done(l.port?.rawValue, nil)
                    case .failed(let e): reported = true; done(nil, e)
                    default: break
                    }
                }
                l.start(queue: self.q)
                self.listener = l
                let b = NWBrowser(for: .bonjour(type: "_waslip._tcp", domain: nil), using: .tcp)
                b.browseResultsChangedHandler = { [weak self] results, _ in
                    guard let self = self else { return }
                    for r in results {
                        if case let .service(peer, _, _, _) = r.endpoint, self.name < peer, !self.dialed.contains(peer) {
                            self.dialed.insert(peer)
                            self.attach(NWConnection(to: r.endpoint, using: .tcp), peer: peer)
                        }
                    }
                }
                b.start(queue: self.q)
                self.browser = b
            } catch { done(nil, error) }
        }
    }

    func dial(host: String, port: UInt16) {
        guard let p = NWEndpoint.Port(rawValue: port) else { return }
        attach(NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp))
    }

    private func attach(_ c: NWConnection, peer: String? = nil) {
        let id = "ip:\(c.endpoint)"
        c.stateUpdateHandler = { [weak self] st in
            guard let self = self else { return }
            switch st {
            case .ready:
                self.conns[id] = c; self.onConnected?(id); self.readFrame(c, id)
            case .failed(let e):
                self.onError?("ip-connect", e.localizedDescription); self.drop(id)
                if let peer = peer { self.dialed.remove(peer) }
            case .cancelled:
                self.drop(id)
                if let peer = peer { self.dialed.remove(peer) }    // allows reconnection when the peer returns
            default: break
            }
        }
        c.start(queue: q)
    }

    private func drop(_ id: String) { if conns.removeValue(forKey: id) != nil { onDisconnected?(id) } }

    private func readFrame(_ c: NWConnection, _ id: String) {
        c.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] head, _, _, err in
            guard let self = self else { return }
            guard err == nil, let head = head, head.count == 4 else { c.cancel(); return }
            let h = [UInt8](head)
            let n = Int(h[0]) << 24 | Int(h[1]) << 16 | Int(h[2]) << 8 | Int(h[3])
            guard n > 0, n <= 4_194_304 else { c.cancel(); return }
            c.receive(minimumIncompleteLength: n, maximumLength: n) { body, _, _, err2 in
                guard err2 == nil, let body = body, body.count == n else { c.cancel(); return }
                self.onData?(id, body)
                self.readFrame(c, id)
            }
        }
    }

    func send(id: String, data: Data, done: @escaping (Bool) -> Void) {
        q.async {
            guard let c = self.conns[id] else { done(false); return }
            let n = UInt32(data.count)
            var frame = Data([UInt8(n >> 24 & 0xFF), UInt8(n >> 16 & 0xFF), UInt8(n >> 8 & 0xFF), UInt8(n & 0xFF)])
            frame.append(data)
            c.send(content: frame, completion: .contentProcessed { e in done(e == nil) })
        }
    }

    // MARK: KISS modem over TCP
    func kissConnect(host: String, port: UInt16, done: @escaping (String?, String?) -> Void) {
        guard let p = NWEndpoint.Port(rawValue: port) else { done(nil, "bad port"); return }
        let id = "kiss:\(host):\(port)"
        let c = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
        var reported = false
        c.stateUpdateHandler = { [weak self] st in
            guard let self = self else { return }
            switch st {
            case .ready:
                self.kiss[id] = c
                if !reported { reported = true; done(id, nil) }
                self.readKiss(c, id)
            case .failed(let e):
                if !reported { reported = true; done(nil, e.localizedDescription) }
                self.kiss.removeValue(forKey: id); self.onKissClosed?(id)
            case .cancelled:
                self.kiss.removeValue(forKey: id); self.onKissClosed?(id)
            default: break
            }
        }
        c.start(queue: q)
    }

    private func readKiss(_ c: NWConnection, _ id: String) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, complete, err in
            guard let self = self else { return }
            if let data = data, !data.isEmpty { self.onKissData?(id, data) }
            if err != nil || complete { c.cancel(); return }
            self.readKiss(c, id)
        }
    }

    func kissSend(id: String, data: Data, done: @escaping (Bool) -> Void) {
        q.async {
            guard let c = self.kiss[id] else { done(false); return }
            c.send(content: data, completion: .contentProcessed { e in done(e == nil) })
        }
    }

    func kissClose(id: String) { q.async { self.kiss.removeValue(forKey: id)?.cancel() } }

    func stop() {
        q.async {
            self.browser?.cancel(); self.listener?.cancel()
            self.conns.values.forEach { $0.cancel() }; self.kiss.values.forEach { $0.cancel() }
            self.conns.removeAll(); self.kiss.removeAll(); self.dialed.removeAll()
            self.browser = nil; self.listener = nil
        }
    }

    static func localAddresses() -> [String] {
        var out: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return out }
        defer { freeifaddrs(ifaddr) }
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard let sa = p.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                let s = String(cString: host)
                if s != "127.0.0.1" { out.append(s) }
            }
        }
        return out
    }
}
