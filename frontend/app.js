/**
 * Phishing Detection - Frontend Application
 * TODO: Implement API integration in Milestone 3
 */

const API_BASE_URL = 'http://localhost:8000';

document.getElementById('analyzeForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const inputUrl = document.getElementById('inputUrl').value.trim();
    const resultsDiv = document.getElementById('results');
    const resultContent = document.getElementById('resultContent');
    
    if (!inputUrl) {
        alert('Please enter a URL or email content');
        return;
    }
    
    // TODO: Replace with actual API call
    resultContent.innerHTML = `
        <p><strong>Input:</strong> ${inputUrl}</p>
        <p><strong>Status:</strong> API integration pending (Milestone 3)</p>
        <p><em>This is a placeholder response.</em></p>
    `;
    
    resultsDiv.classList.remove('hidden');
});
