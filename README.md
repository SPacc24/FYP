# AutoPenTest

AutoPenTest is a Flask-based web application designed for automated penetration testing using MITRE Caldera. It provides a RESTful API interface to interact with Caldera servers, manage operations, and generate reports.

## Features

- **Caldera Integration**: Connects to MITRE Caldera servers for red teaming operations
- **Operation Management**: Start, monitor, and manage penetration testing operations
- **Agent Monitoring**: Check status of Caldera agents and their readiness
- **Logging**: Automatic logging of operations and results to JSON files
- **Web Interface**: Basic Flask web app with API endpoints (frontend templates are under development)
- **Modular Architecture**: Organized into separate modules for API client, operations, scanners, and reports

## Project Structure

```
project/
├── app.py                 # Main Flask application
├── config.py              # Configuration settings (under development)
├── db.py                  # Database utilities (under development)
├── cleanup.py             # Cleanup utilities
├── requirements.txt       # Python dependencies
├── caldera/               # Caldera integration module
│   ├── __init__.py
│   ├── api_client.py      # Caldera API client
│   └── operation_manager.py # Operation management
├── docs/                  # Documentation (under development)
├── reports/               # Report generation (under development)
├── scanners/              # Scanning utilities (under development)
├── static/                # Static assets (CSS, JS)
├── storage/               # Data storage
│   └── logs/              # Operation logs
├── templates/             # HTML templates (under development)
├── tests/                 # Test suite
└── utils/                 # Utility functions
```

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd project
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   Create a `.env` file in the project root with:
   ```

   SECRET_KEY=some-random-secret
   DEBUG=true
   CALDERA_URL=http://127.0.0.1:8888
   CALDERA_API_KEY=your-caldera-api-key
   AGENT_GROUP=red
   KALI_IP=192.168.xx.xx
   OPERATION_TIMEOUT=180
   MYSQL_HOST=192.168.xx.xx
   MYSQL_USER=autopentest
   MYSQL_PASS=your-password
   MYSQL_DB=autopentest
   ```

4. Ensure MITRE Caldera is running and accessible.

## Usage

### Running the Application

Start the Flask app:
```bash
python app.py
```

The app will run on `http://127.0.0.1:5000` by default.

### API Endpoints

- `GET /`: Basic status page
- `GET /caldera/status`: Check Caldera connectivity and agent status
- `POST /caldera/run`: Start a new operation
  - Required: `adversary_id`
  - Optional: `selected_techniques`, `group`, `planner_id`
- `GET /caldera/operation/<operation_id>`: Poll operation status

### Example API Usage

Check Caldera status:
```bash
curl http://127.0.0.1:5000/caldera/status
```

Start an operation:
```bash
curl -X POST http://127.0.0.1:5000/caldera/run \
  -H "Content-Type: application/json" \
  -d '{"adversary_id": "your-adversary-id"}'
```

## Dependencies

- Flask 3.0.0
- requests 2.31.0
- python-dotenv 1.0.1
- responses (for testing)
- pytest 7.2.0

## Testing

Run tests with:
```bash
pytest
```

Test files are located in the `tests/` directory.

## Development Status

This project is currently in development. Key components implemented:

- ✅ Caldera API client
- ✅ Operation management
- ✅ Basic Flask API
- ✅ Logging system

Under development:
- 🔄 Web interface templates
- 🔄 Report generation
- 🔄 Scanning utilities
- 🔄 Database integration
- 🔄 Configuration management

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add license information here]

## Acknowledgments

- Built using MITRE Caldera for red teaming capabilities
- Flask framework for web application</content>
