import dotenv from 'dotenv';

dotenv.config();

const BLACK = '\x1b[30m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const MAGENTA = '\x1b[35m'; // Purple/Magenta
const CYAN = '\x1b[36m';
const WHITE = '\x1b[37m';
const BRIGHT_BLACK = '\x1b[90m';
const BRIGHT_RED = '\x1b[91m';
const BRIGHT_GREEN = '\x1b[92m';
const BRIGHT_YELLOW = '\x1b[93m';
const BRIGHT_BLUE = '\x1b[94m';
const BRIGHT_MAGENTA = '\x1b[95m'; // Bright Purple/Magenta
const BRIGHT_CYAN = '\x1b[96m';
const BRIGHT_WHITE = '\x1b[97m';

const TEXT_COLOR = YELLOW;
const RESET = '\x1b[0m'; // Reset to default style

export const dd = (text, options?: any) => {
	let payload;
	const projectId = process.env.PROJECT_ID ?? 'UNKNOWN_PROJECT';
    
	// Simple caller info extraction
	const getCallerInfo = () => {
		const stack = new Error().stack?.split('\n') || [];
		// Look for the third line in stack (caller of this function)
		const callerFrame = stack[3] || '';
		const match = callerFrame.match(/([^\/\\]+):(\d+):(\d+)/);
		if (match) {
			return `${match[1]}:${match[2]}`;
		}
		return 'unknown:0';
	};
    
	const callerInfo = getCallerInfo();
	const prefix = `[${projectId}] ${callerInfo}`;
    
	// Check if we should use two-line format
	const useTwoLines = (input) => {
		if (input === null) return false;
		if (typeof input === 'object') return true;
        
		if (typeof input === 'string') {
			try {
				const parsed = JSON.parse(input);
				return typeof parsed === 'object' && parsed !== null;
			} catch {
				return false;
			}
		}
        
		return false;
	};
    
	if (useTwoLines(text)) {
		console.log(`${TEXT_COLOR}${prefix}${RESET}`);
        
		payload = text;
		if (typeof text === 'string') {
			try {
				payload = JSON.parse(text);
			} catch {
				// Keep as string if parsing fails
			}
		}
        
		console.log(payload);
	} else {
		console.log(`${TEXT_COLOR}${prefix} ${text}${RESET}`);
	}
}