/**
 * PhishGuard Frontend Core - Vanilla JavaScript
 * Handles API fetch requests, UI updates, mobile sidebar, and notifications.
 */

// Global PhishGuard namespace
window.PhishGuard = {
  /**
   * Display a floating toast notification.
   * @param {string} message
   * @param {'success'|'error'|'info'} type
   */
  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <span class="toast-msg">${message}</span>
      <button class="toast-close" type="button">&times;</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => {
      toast.remove();
    });

    container.appendChild(toast);
    setTimeout(() => {
      if (toast.parentElement) toast.remove();
    }, 4500);
  },

  /**
   * Safe Fetch API wrapper returning JSON.
   * @param {string} url
   * @param {RequestInit} options
   */
  async request(url, options = {}) {
    try {
      const response = await fetch(url, options);
      const data = await response.json().catch(() => null);

      if (!response.ok || (data && data.success === false)) {
        const errorMsg = (data && data.error) ? data.error : `HTTP Error ${response.status}`;
        throw new Error(errorMsg);
      }
      return data;
    } catch (err) {
      this.showToast(err.message, 'error');
      throw err;
    }
  },

  /**
   * Helper to format risk pill HTML.
   */
  getRiskPill(level) {
    const lvl = (level || 'Unknown').toLowerCase();
    return `<span class="pill ${lvl}">${level} Risk</span>`;
  },

  /**
   * Helper to get risk score color class.
   */
  getScoreClass(score) {
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }
};

// Initialize common behaviors
document.addEventListener('DOMContentLoaded', () => {
  // Mobile sidebar drawer toggle
  const toggleBtn = document.getElementById('mobile-toggle');
  const sidebar = document.getElementById('app-sidebar');
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });

    // Close when clicking outside on mobile
    document.addEventListener('click', (e) => {
      if (sidebar.classList.contains('open') && !sidebar.contains(e.target) && e.target !== toggleBtn) {
        sidebar.classList.remove('open');
      }
    });
  }
});
