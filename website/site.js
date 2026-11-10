const copyButton = document.querySelector('#copy');
const copyStatus = document.querySelector('#copy-status');

if (navigator.clipboard?.writeText) {
  copyButton.hidden = false;
  copyButton.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(document.querySelector('#install-command').textContent);
      copyStatus.textContent = 'Command copied.';
    } catch {
      copyStatus.textContent = 'Could not copy. Select the command and copy it manually.';
    }
  });
}
