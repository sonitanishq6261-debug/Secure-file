"use strict";

const STARTER_ID = "Tanishq111";
const STARTER_PASSWORD = "Tanishq@111";
const CONFIG_KEY = "securefs.v1.config";
const DB_NAME = "securefs-vault";
const STORE_NAME = "files";
const FOLDER_STORE = "folders";
const MIGRATION_KEY = "securefs.projectStorageMigrated.v1";
const API_BASE = location.hostname === "127.0.0.1" && location.port === "8000" ? "" : "http://127.0.0.1:8000";
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

let vaultKey = null;
let files = [];
let folders = [];
let activeFolderId = "all";
let previewUrl = null;
let toastTimer = null;

const $ = (selector) => document.querySelector(selector);
const authModal = $("#auth-modal");
const authForm = $("#auth-form");
const authError = $("#auth-error");

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function getConfig() {
  try { return JSON.parse(localStorage.getItem(CONFIG_KEY) || "null"); }
  catch { return null; }
}

function saveConfig(config) { localStorage.setItem(CONFIG_KEY, JSON.stringify(config)); }

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function seal(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function openSeal(key, sealed) {
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(sealed.iv) }, key, base64ToBytes(sealed.data));
  return decoder.decode(plaintext);
}

async function apiRequest(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, { cache: "no-store", ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
  } catch {
    throw new Error("SecureFS server is not reachable. Run `py server.py` in the project folder, then open http://127.0.0.1:8000.");
  }
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 404) throw new Error("SecureFS storage API was not found. Start `py server.py` from the project folder and keep it running at http://127.0.0.1:8000.");
    throw new Error(result.error || `Storage request failed (${response.status}).`);
  }
  return result;
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 2);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME, { keyPath: "id" });
      if (!db.objectStoreNames.contains(FOLDER_STORE)) db.createObjectStore(FOLDER_STORE, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbAll(storeName = STORE_NAME) {
  return apiRequest(storeName === FOLDER_STORE ? "/api/folders" : "/api/files");
}

async function dbPut(record, storeName = STORE_NAME) {
  return apiRequest(storeName === FOLDER_STORE ? "/api/folders" : "/api/files", { method: "POST", body: JSON.stringify(record) });
}

async function dbDelete(id, storeName = STORE_NAME, folderId = "root") {
  const suffix = storeName === STORE_NAME ? `?folderId=${encodeURIComponent(folderId)}` : "";
  return apiRequest(`/api/${storeName === FOLDER_STORE ? "folders" : "files"}/${encodeURIComponent(id)}${suffix}`, { method: "DELETE" });
}

async function migrateBrowserVault() {
  if (localStorage.getItem(MIGRATION_KEY) === "true") return;
  const db = await openDatabase();
  const existing = await new Promise((resolve, reject) => {
    const stores = [STORE_NAME, FOLDER_STORE].filter((name) => db.objectStoreNames.contains(name));
    if (!stores.length) return resolve({ files: [], folders: [] });
    const tx = db.transaction(stores, "readonly");
    const result = { files: [], folders: [] };
    if (stores.includes(STORE_NAME)) {
      const request = tx.objectStore(STORE_NAME).getAll();
      request.onsuccess = () => { result.files = request.result; };
    }
    if (stores.includes(FOLDER_STORE)) {
      const request = tx.objectStore(FOLDER_STORE).getAll();
      request.onsuccess = () => { result.folders = request.result; };
    }
    tx.oncomplete = () => resolve(result);
    tx.onerror = () => reject(tx.error);
  });
  db.close();
  for (const record of existing.folders) await dbPut(record, FOLDER_STORE);
  for (const record of existing.files) await dbPut({ ...record, folderId: record.folderId || "root" }, STORE_NAME);
  localStorage.setItem(MIGRATION_KEY, "true");
}

async function loadFiles() {
  const records = await dbAll();
  files = [];
  let lockedCount = 0;
  for (const record of records) {
    try {
      const info = JSON.parse(await openSeal(vaultKey, record.payload));
      files.push({ id: record.id, folderId: record.folderId || "root", ...info, storedSize: base64ToBytes(info.content).length });
    } catch {
      lockedCount += 1;
    }
  }
  renderFiles();
  if (lockedCount) showToast(`${lockedCount} saved file${lockedCount === 1 ? " could" : "s could"} not be unlocked. Use the same login and browser profile used for upload.`);
}

async function loadFolders() {
  const records = await dbAll(FOLDER_STORE);
  folders = [];
  for (const record of records) {
    const info = JSON.parse(await openSeal(vaultKey, record.payload));
    folders.push({ id: record.id, name: info.name, createdAt: info.createdAt });
  }
  renderFolders();
}

function renderFolders() {
  const select = $("#folder-select");
  select.replaceChildren();
  const all = document.createElement("option");
  all.value = "all";
  all.textContent = "All files";
  select.append(all);
  for (const folder of folders.sort((a, b) => a.name.localeCompare(b.name))) {
    const option = document.createElement("option");
    option.value = folder.id;
    option.textContent = folder.name;
    select.append(option);
  }
  if (activeFolderId !== "all" && !folders.some((folder) => folder.id === activeFolderId)) activeFolderId = "all";
  select.value = activeFolderId;
}

function showModal(modal, visible) {
  modal.classList.toggle("visible", visible);
  modal.setAttribute("aria-hidden", String(!visible));
}

function readableSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function fileIcon(name) {
  const ext = name.split(".").pop().toLowerCase();
  if (["png", "jpg", "jpeg", "gif", "webp", "svg"].includes(ext)) return ["▧", "image"];
  if (["pdf"].includes(ext)) return ["▤", "pdf"];
  if (["doc", "docx", "txt", "rtf"].includes(ext)) return ["≡", "document"];
  if (["zip", "rar", "7z"].includes(ext)) return ["▣", "archive"];
  return ["◇", "other"];
}

function renderFiles() {
  const query = $("#search-input").value.trim().toLowerCase();
  const folderFiles = files.filter((file) => activeFolderId === "all" || file.folderId === activeFolderId);
  const filtered = folderFiles.filter((file) => file.name.toLowerCase().includes(query)).sort((a, b) => b.addedAt - a.addedAt);
  const tbody = $("#file-list");
  tbody.replaceChildren();
  for (const file of filtered) {
    const tr = document.createElement("tr");
    const [icon, iconClass] = fileIcon(file.name);
    const name = document.createElement("td");
    name.className = "name-cell";
    name.innerHTML = `<span class="file-icon ${iconClass}">${icon}</span>`;
    const nameCopy = document.createElement("span");
    nameCopy.className = "file-name";
    nameCopy.textContent = file.name;
    name.append(nameCopy);
    const size = document.createElement("td");
    size.className = "size-cell";
    size.textContent = readableSize(file.storedSize);
    const date = document.createElement("td");
    date.className = "date-cell";
    date.textContent = new Date(file.addedAt).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
    const actions = document.createElement("td");
    actions.className = "action-cell";
    const isPdf = file.type === "application/pdf" || file.name.toLowerCase().endsWith(".pdf");
    if (isPdf) {
      const preview = document.createElement("button");
      preview.className = "row-action preview-action";
      preview.type = "button";
      preview.textContent = "View";
      preview.title = `View PDF ${file.name}`;
      preview.setAttribute("aria-label", `View ${file.name}`);
      preview.addEventListener("click", () => previewPdf(file));
      actions.append(preview);
    }
    const download = document.createElement("button");
    download.className = "row-action download-action";
    download.type = "button";
    download.textContent = "↓";
    download.title = `Download ${file.name}`;
    download.setAttribute("aria-label", `Download ${file.name}`);
    download.addEventListener("click", () => downloadFile(file));
    const remove = document.createElement("button");
    remove.className = "row-action delete-action";
    remove.type = "button";
    remove.textContent = "×";
    remove.title = `Delete ${file.name}`;
    remove.setAttribute("aria-label", `Delete ${file.name}`);
    remove.addEventListener("click", () => deleteFile(file));
    actions.append(download, remove);
    tr.append(name, size, date, actions);
    tbody.append(tr);
  }
  $("#file-total").textContent = String(files.length);
  $("#nav-count").textContent = String(files.length);
  $("#vault-size").textContent = readableSize(files.reduce((sum, file) => sum + file.storedSize, 0));
  $("#empty-state").classList.toggle("hidden", folderFiles.length > 0 || Boolean(query));
  $(".file-table").classList.toggle("hidden", folderFiles.length === 0 || filtered.length === 0);
  if (folderFiles.length > 0 && filtered.length === 0) {
    const empty = $("#empty-state");
    empty.classList.remove("hidden");
    empty.querySelector("strong").textContent = "No matching files";
    empty.querySelector("p").textContent = "Try another name or clear your search.";
    $("#empty-add-button").classList.add("hidden");
  } else {
    const selectedFolder = folders.find((folder) => folder.id === activeFolderId);
    $("#empty-state strong").textContent = selectedFolder ? `No files in ${selectedFolder.name} yet` : "Your vault is ready";
    $("#empty-state p").textContent = selectedFolder ? "Upload files here to keep them together." : "Upload a file to encrypt it and keep it here.";
    $("#empty-add-button").classList.remove("hidden");
  }
  const selectedFolder = folders.find((folder) => folder.id === activeFolderId);
  $("#files-heading").textContent = selectedFolder ? selectedFolder.name : "Your files";
  $("#file-subtitle").textContent = `${folderFiles.length} ${folderFiles.length === 1 ? "file" : "files"} ${selectedFolder ? "in this folder" : "in your vault"}.`;
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 2800);
}

async function importFiles(fileList) {
  const chosen = [...fileList];
  if (!chosen.length) return;
  $("#upload-success").classList.add("hidden");
  const uploaded = [];
  const failed = [];
  for (const file of chosen) {
    if (file.size > MAX_FILE_SIZE) {
      failed.push(`${file.name} (over 10 MB)`);
      continue;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const payload = JSON.stringify({ name: file.name, type: file.type || "application/octet-stream", addedAt: Date.now(), content: bytesToBase64(bytes) });
      const sealed = await seal(vaultKey, payload);
      await dbPut({ id: crypto.randomUUID(), folderId: activeFolderId === "all" ? "root" : activeFolderId, payload: sealed });
      uploaded.push(file.name);
    } catch (error) {
      failed.push(`${file.name} (${error.message || "upload failed"})`);
    }
  }
  await loadFiles();
  if (uploaded.length) {
    const folderName = folders.find((folder) => folder.id === activeFolderId)?.name;
    $("#upload-success-details").textContent = `${uploaded.join(", ")} ${folderName ? `saved in ${folderName}` : "encrypted and saved successfully"}.`;
    $("#upload-success").classList.remove("hidden");
  }
  if (failed.length) showToast(`Could not upload: ${failed.join(", ")}`);
  $("#file-input").value = "";
}

function downloadFile(file) {
  const blob = new Blob([base64ToBytes(file.content)], { type: file.type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = file.name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast("Your file has been unlocked for download.");
}

function previewPdf(file) {
  closePdfPreview();
  const blob = new Blob([base64ToBytes(file.content)], { type: "application/pdf" });
  previewUrl = URL.createObjectURL(blob);
  $("#pdf-title").textContent = file.name;
  $("#pdf-frame").src = previewUrl;
  showModal($("#pdf-modal"), true);
}

function closePdfPreview() {
  showModal($("#pdf-modal"), false);
  $("#pdf-frame").removeAttribute("src");
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
}

async function deleteFile(file) {
  if (!window.confirm(`Delete “${file.name}” from this vault?`)) return;
  await dbDelete(file.id, STORE_NAME, file.folderId);
  await loadFiles();
  showToast("File removed from your vault.");
}

function lockVault() {
  vaultKey = null;
  files = [];
  folders = [];
  activeFolderId = "all";
  $("#search-input").value = "";
  renderFolders();
  renderFiles();
  $("#auth-form").reset();
  $("#auth-error").textContent = "";
  showModal(authModal, true);
  setTimeout(() => $("#user-id").focus(), 50);
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = $("#user-id").value.trim();
  const password = $("#user-password").value;
  const submit = $("#auth-submit");
  submit.disabled = true;
  submit.innerHTML = "Unlocking…";
  authError.textContent = "";
  try {
    const config = getConfig();
    if (!config) {
      if (id !== STARTER_ID || password !== STARTER_PASSWORD) throw new Error("Those credentials didn't match the first-time demo login.");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveKey(password, salt);
      const check = await seal(key, "SecureFS vault check v1");
      saveConfig({ id, salt: bytesToBase64(salt), check });
      vaultKey = key;
      $("#demo-note").classList.add("hidden");
      showToast("Vault created. Your files are encrypted on this device.");
    } else {
      if (id !== config.id) throw new Error("That user ID or password is incorrect.");
      const key = await deriveKey(password, base64ToBytes(config.salt));
      if (await openSeal(key, config.check) !== "SecureFS vault check v1") throw new Error("That user ID or password is incorrect.");
      vaultKey = key;
    }
    await migrateBrowserVault();
    await loadFolders();
    await loadFiles();
    showModal(authModal, false);
  } catch (error) {
    authError.textContent = error instanceof DOMException && error.name === "OperationError" ? "That user ID or password is incorrect." : (error.message || "Could not open this vault. Please try again.");
    vaultKey = null;
  } finally {
    submit.disabled = false;
    submit.innerHTML = 'Unlock vault <span>→</span>';
  }
});

$("#show-password").addEventListener("click", (event) => {
  const input = $("#user-password");
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  event.currentTarget.textContent = showing ? "Show" : "Hide";
});

$("#logout-button").addEventListener("click", lockVault);
$("#search-input").addEventListener("input", renderFiles);
$("#folder-select").addEventListener("change", (event) => {
  activeFolderId = event.target.value;
  $("#search-input").value = "";
  $("#upload-success").classList.add("hidden");
  renderFiles();
});
$("#new-folder-button").addEventListener("click", () => {
  $("#folder-form").reset();
  $("#folder-error").textContent = "";
  showModal($("#folder-modal"), true);
  $("#folder-name").focus();
});
$("#close-folder-modal").addEventListener("click", () => showModal($("#folder-modal"), false));
$("#folder-modal").addEventListener("click", (event) => { if (event.target === $("#folder-modal")) showModal($("#folder-modal"), false); });
$("#folder-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = $("#folder-name").value.trim();
  if (!name) return;
  if (folders.some((folder) => folder.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
    $("#folder-error").textContent = "A folder with that name already exists.";
    return;
  }
  try {
    const id = crypto.randomUUID();
    const payload = await seal(vaultKey, JSON.stringify({ name, createdAt: Date.now() }));
    await dbPut({ id, payload }, FOLDER_STORE);
    folders.push({ id, name, createdAt: Date.now() });
    activeFolderId = id;
    renderFolders();
    renderFiles();
    showModal($("#folder-modal"), false);
    showToast(`Folder “${name}” created.`);
  } catch (error) {
    $("#folder-error").textContent = error.message || "Could not create the folder.";
  }
});
$("#dismiss-success").addEventListener("click", () => $("#upload-success").classList.add("hidden"));
$("#close-pdf-modal").addEventListener("click", closePdfPreview);
$("#pdf-modal").addEventListener("click", (event) => { if (event.target === $("#pdf-modal")) closePdfPreview(); });
$("#file-input").addEventListener("change", (event) => importFiles(event.target.files));
$("#add-button").addEventListener("click", () => $("#file-input").click());
$("#browse-button").addEventListener("click", () => $("#file-input").click());
$("#empty-add-button").addEventListener("click", () => $("#file-input").click());
$("#drop-zone").addEventListener("click", (event) => { if (!event.target.closest("button")) $("#file-input").click(); });
$("#drop-zone").addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); $("#file-input").click(); } });
$("#drop-zone").addEventListener("dragover", (event) => { event.preventDefault(); $("#drop-zone").classList.add("dragging"); });
$("#drop-zone").addEventListener("dragleave", () => $("#drop-zone").classList.remove("dragging"));
$("#drop-zone").addEventListener("drop", (event) => { event.preventDefault(); $("#drop-zone").classList.remove("dragging"); importFiles(event.dataTransfer.files); });
$("#help-button").addEventListener("click", () => showModal($("#about-modal"), true));
$("#close-about").addEventListener("click", () => showModal($("#about-modal"), false));
$("#about-modal").addEventListener("click", (event) => { if (event.target === $("#about-modal")) showModal($("#about-modal"), false); });
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    showModal($("#about-modal"), false);
    showModal($("#folder-modal"), false);
    closePdfPreview();
  }
});

$("#user-id").value = STARTER_ID;
if (getConfig()) $("#demo-note").classList.add("hidden");
showModal(authModal, true);
