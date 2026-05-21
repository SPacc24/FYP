function escapeChatHtml(value) {
  if (value === null || value === undefined) return "";

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatAiReply(value) {
  return escapeChatHtml(value || "No reply returned.")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/\n/g, "<br>");
}

async function sendAiChatMessage() {
  const input = document.getElementById("aiChatInput");
  const chatBox = document.getElementById("aiChatBox");
  const sendBtn = document.getElementById("aiChatSendBtn");

  if (!input || !chatBox) return;

  const message = input.value.trim();
  if (!message) return;

  input.value = "";

  if (sendBtn) {
    sendBtn.disabled = true;
    sendBtn.textContent = "Asking...";
  }

  chatBox.innerHTML += `
    <div class="ai-message ai-message-user">
      <strong>You</strong>
      <p>${escapeChatHtml(message)}</p>
    </div>
  `;

  chatBox.innerHTML += `
    <div class="ai-message ai-message-assistant muted" id="aiThinking">
      <strong>AI</strong>
      <p>Thinking...</p>
    </div>
  `;

  chatBox.scrollTop = chatBox.scrollHeight;

  try {
    const res = await fetch("/ai/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: message
      })
    });

    const data = await res.json();

    const thinking = document.getElementById("aiThinking");
    if (thinking) thinking.remove();

    chatBox.innerHTML += `
      <div class="ai-message ai-message-assistant">
        <strong>AI</strong>
        <p>${formatAiReply(data.reply)}</p>
      </div>
    `;
  } catch (err) {
    const thinking = document.getElementById("aiThinking");
    if (thinking) thinking.remove();

    chatBox.innerHTML += `
      <div class="ai-message ai-message-assistant">
        <strong>AI</strong>
        <p>Could not reach AI chat endpoint.</p>
      </div>
    `;
  }

  if (sendBtn) {
    sendBtn.disabled = false;
    sendBtn.textContent = "Ask";
  }

  chatBox.scrollTop = chatBox.scrollHeight;
}

document.addEventListener("DOMContentLoaded", function () {
  const sendBtn = document.getElementById("aiChatSendBtn");
  const input = document.getElementById("aiChatInput");

  if (sendBtn) {
    sendBtn.addEventListener("click", sendAiChatMessage);
  }

  if (input) {
    input.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        sendAiChatMessage();
      }
    });
  }
});