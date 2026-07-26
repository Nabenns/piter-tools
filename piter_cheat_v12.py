#!/usr/bin/env python3
"""
Piter Cheat v12 — Background-safe
Output ke file, gak butuh terminal.
"""
import sys, time, json, os

OUTPUT_FILE = '/tmp/piter_v12_output.txt'

# Import done, now attach as background
import frida

def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    
    with open(OUTPUT_FILE, 'w') as out:
        out.write(f"[START] pid={pid}\n")
        out.flush()
        
        try:
            if pid:
                session = frida.attach(pid)
            else:
                session = frida.attach('Growtopia')
            
            out.write(f"[ATTACHED] PID={session._impl.pid}\n")
            out.flush()
            
            agent_path = os.path.join(os.path.dirname(__file__), 'piter_agent_v11.js')
            with open(agent_path) as f:
                agent_code = f.read()
            
            script = session.create_script(agent_code)
            
            def on_msg(msg, data):
                try:
                    with open(OUTPUT_FILE, 'a') as o:
                        if msg['type'] == 'log':
                            o.write(msg['payload'] + '\n')
                        elif msg['type'] == 'send':
                            payload = msg.get('payload', '')
                            if isinstance(payload, dict) and payload.get('type') == 'packet':
                                o.write(f"[{payload['dir']}] #{payload['num']} | {payload['size']}B\n")
                                o.write(f"HEX: {payload['hex']}\n")
                                o.write('---\n')
                            else:
                                o.write(f"[agent] {payload}\n")
                        o.flush()
                except:
                    pass
            
            script.on('message', on_msg)
            script.load()
            
            out.write("[LOADED] Agent injected\n")
            out.flush()
            
            while True:
                time.sleep(5)
                with open(OUTPUT_FILE, 'a') as o:
                    o.write(f"[HEARTBEAT] {time.ctime()}\n")
                    o.flush()
                
        except Exception as e:
            with open(OUTPUT_FILE, 'a') as o:
                o.write(f"[ERROR] {e}\n")
            sys.exit(1)

if __name__ == '__main__':
    main()
