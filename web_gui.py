#!/usr/bin/env python3
"""
web gui for dns resolver with flask
"""

from flask import Flask, render_template, request, jsonify, session
import json
import os
from datetime import datetime
from parallel_dns_resolver import ParallelDNSResolver

app = Flask(__name__)
app.secret_key = 'dns_resolver_secret_key_2024'

# global resolver instance
resolver = ParallelDNSResolver(use_cache=True, max_workers=5, max_retries=3)

# record types for the gui
RECORD_TYPES = [
    {'value': 'A', 'label': 'A (IPv4 Address)'},
    {'value': 'AAAA', 'label': 'AAAA (IPv6 Address)'},
    {'value': 'CNAME', 'label': 'CNAME (Canonical Name)'},
    {'value': 'MX', 'label': 'MX (Mail Exchange)'},
    {'value': 'TXT', 'label': 'TXT (Text Record)'},
    {'value': 'NS', 'label': 'NS (Name Server)'},
]

@app.route('/')
def index():
    """main page"""
    return render_template('index.html', record_types=RECORD_TYPES)

@app.route('/resolve', methods=['POST'])
def resolve_domain():
    """resolve domain via ajax"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        record_type = data.get('record_type', 'A')
        
        if not domain:
            return jsonify({'error': 'domain is required'}), 400
        
        # resolve the domain
        start_time = datetime.now()
        results = resolver.resolve(domain, record_type)
        end_time = datetime.now()
        
        resolution_time = (end_time - start_time).total_seconds()
        
        # format results
        formatted_results = []
        for result in results:
            if record_type == 'MX':
                # mx records are already formatted as "priority exchange"
                formatted_results.append(result)
            else:
                formatted_results.append(result)
        
        # get resolution steps for display
        steps = []
        for i, step in enumerate(resolver.resolution_steps, 1):
            step_info = {
                'step': i,
                'server': step['server'],
                'domain': step['domain'],
                'record_type': step['record_type'],
                'response_time': f"{step['response_time']:.3f}s",
                'success': step['success'],
                'results': step.get('results', []),
                'authorities': step.get('authorities', []),
                'additionals': step.get('additionals', [])
            }
            if not step['success']:
                step_info['error'] = step.get('error', 'Unknown error')
            steps.append(step_info)
        
        # save to history
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'domain': domain,
            'record_type': record_type,
            'results': formatted_results,
            'resolution_time': resolution_time,
            'steps_count': len(steps)
        }
        
        if 'history' not in session:
            session['history'] = []
        
        session['history'].insert(0, history_entry)
        # keep only last 20 entries
        session['history'] = session['history'][:20]
        
        return jsonify({
            'success': True,
            'domain': domain,
            'record_type': record_type,
            'results': formatted_results,
            'resolution_time': resolution_time,
            'steps': steps,
            'cache_hit': len(formatted_results) > 0  # simple cache detection
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/history')
def get_history():
    """get resolution history"""
    history = session.get('history', [])
    return jsonify(history)

@app.route('/clear-history', methods=['POST'])
def clear_history():
    """clear resolution history"""
    session['history'] = []
    return jsonify({'success': True})

@app.route('/cache-info')
def cache_info():
    """get cache information"""
    try:
        cache_file = resolver.cache.cache_file
        memory_count = len(resolver.cache.memory_cache)
        file_count = len(resolver.cache.file_cache)
        
        return jsonify({
            'cache_file': cache_file,
            'memory_entries': memory_count,
            'file_entries': file_count,
            'total_entries': memory_count + file_count
        })
    except:
        return jsonify({'error': 'cache not available'})

@app.route('/clear-cache', methods=['POST'])
def clear_cache():
    """clear dns cache"""
    try:
        resolver.cache.memory_cache.clear()
        resolver.cache.file_cache.clear()
        resolver.cache.save_cache()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """settings page"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            max_workers = int(data.get('max_workers', 5))
            max_retries = int(data.get('max_retries', 3))
            use_cache = data.get('use_cache', True)
            
            # update resolver settings
            resolver.max_workers = max_workers
            resolver.max_retries = max_retries
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return jsonify({
        'max_workers': resolver.max_workers,
        'max_retries': resolver.max_retries,
        'use_cache': resolver.cache is not None
    })

if __name__ == '__main__':
    # create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    print("🌐 dns resolver web gui")
    print("📡 starting server on http://localhost:5000")
    print("🔧 press ctrl+c to stop")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 