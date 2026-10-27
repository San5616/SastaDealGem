/**
 * ============================================================================
 * SASTADEAL — PRODUCTION BACKEND API (Code.gs)
 * ============================================================================
 * Database : Google Sheets (Orders, Tracking, Accounts, Mediator, Platform,
 *            Deals, DealRequests, Dashboard, Instructions)
 * Features : HMAC Signed Tokens, Role-Enforced Data Filtering, ArrayFormula-Safe
 *            Updates, Ghost-Row Prevention, Bulk Updates, Batch Settlements,
 *            Sheet Health Audit & Repair, CallMeBot WhatsApp, GmailApp, Drive Upload.
 * ============================================================================
 */

// ─── 1. PRIVATE SERVER SECRETS (Update these 5 constants) ──────────────────
const SHEET_ID          = 'YOUR_GOOGLE_SHEET_ID_HERE';
const DRIVE_FOLDER_ID   = 'YOUR_GOOGLE_DRIVE_FOLDER_ID_HERE';
const ADMIN_PASSWORD    = 'SastaDeal@2025';
const CALLMEBOT_API_KEY = 'YOUR_CALLMEBOT_API_KEY_HERE';
const ADMIN_WHATSAPP    = '917004984949';
const TOKEN_SECRET      = 'SD_HMAC_SECRET_' + ADMIN_PASSWORD + '_2026';

// Exact Sheet Tab Names
const TABS = {
  ORDERS:        'Orders',
  TRACKING:      'Tracking',
  ACCOUNTS:      'Accounts',
  MEDIATOR:      'Mediator',
  PLATFORM:      'Platform',
  DEALS:         'Deals',
  DEAL_REQUESTS: 'DealRequests',
  DASHBOARD:     'Dashboard',
  INSTRUCTIONS:  'Instructions'
};

// ─── 2. HTTP ENTRY POINTS (GET & POST) ─────────────────────────────────────

function doGet(e) {
  return handleRequest(e, 'GET');
}

function doPost(e) {
  return handleRequest(e, 'POST');
}

function handleRequest(e, method) {
  try {
    let params = (e && e.parameter) ? Object.assign({}, e.parameter) : {};
    if (method === 'POST' && e && e.postData && e.postData.contents) {
      try {
        const body = JSON.parse(e.postData.contents);
        params = Object.assign(params, body);
      } catch (parseErr) {
        // Fallback if urlencoded
      }
    }

    const action = String(params.action || '').trim();
    if (!action) {
      return jsonResponse({ success: false, error: 'Missing action parameter' });
    }

    // Public endpoints (No Auth Token Required)
    switch (action) {
      case 'getPublicHomeData':
        return jsonResponse(getPublicHomeData());
      case 'trackOrder':
        return jsonResponse(trackOrderByPlatformID(params.platformOrderId));
      case 'getPublicDeals':
        return jsonResponse(getDealsList(params.token));
      case 'login':
        return jsonResponse(handleLogin(params));
      case 'registerAccount':
        return jsonResponse(handleRegisterAccount(params));
      case 'forgotPassword':
        return jsonResponse(handleForgotPassword(params));
    }

    // Authenticated endpoints (Verify HMAC Token)
    const auth = verifyToken(params.token);
    if (!auth.valid) {
      return jsonResponse({ success: false, error: 'Unauthorized or session expired. Please login again.', code: 401 });
    }

    switch (action) {
      // Shared / Role-filtered data fetch
      case 'getDashboardData':
        return jsonResponse(getDashboardDataForRole(auth, params));
      case 'getOrderByPlatformID':
        return jsonResponse(getOrderByIdentifier(params.query, auth));
      case 'submitQuery':
        return jsonResponse(handleSubmitQuery(auth, params));

      // Buyer & Admin endpoints
      case 'addOrder':
        return jsonResponse(handleAddOrder(auth, params));
      case 'requestDeal':
        return jsonResponse(handleRequestDeal(auth, params));
      case 'uploadScreenshot':
        return jsonResponse(handleUploadScreenshot(auth, params));

      // Mediator & Admin endpoints
      case 'updateMediatorNote':
        return jsonResponse(handleMediatorNote(auth, params));

      // Admin-Only endpoints
      case 'updateOrderFull':
        requireAdmin(auth);
        return jsonResponse(handleUpdateOrderFull(params));
      case 'updateOrderStatus':
        requireAdmin(auth);
        return jsonResponse(handleUpdateOrderStatus(params));
      case 'updateOrderPayment':
        requireAdmin(auth);
        return jsonResponse(handleUpdateOrderPayment(params));
      case 'updateOrderTracking':
        requireAdmin(auth);
        return jsonResponse(handleUpdateOrderTracking(params));
      case 'bulkUpdateOrders':
        requireAdmin(auth);
        return jsonResponse(handleBulkUpdateOrders(params));
      case 'batchSettleParentBuyer':
        requireAdmin(auth);
        return jsonResponse(handleBatchSettleParentBuyer(params));
      case 'deleteOrder':
        requireAdmin(auth);
        return jsonResponse(handleDeleteOrder(params.orderNo));
      case 'saveAccount':
        requireAdmin(auth);
        return jsonResponse(handleSaveAccount(params));
      case 'deleteAccount':
        requireAdmin(auth);
        return jsonResponse(handleDeleteAccount(params.userId));
      case 'saveMediator':
        requireAdmin(auth);
        return jsonResponse(handleSaveMediator(params));
      case 'deleteMediator':
        requireAdmin(auth);
        return jsonResponse(handleDeleteMediator(params.name));
      case 'saveDeal':
        requireAdmin(auth);
        return jsonResponse(handleSaveDeal(params));
      case 'deleteDeal':
        requireAdmin(auth);
        return jsonResponse(handleDeleteDeal(params.dealId));
      case 'updateDealRequestStatus':
        requireAdmin(auth);
        return jsonResponse(handleUpdateDealRequest(params));
      case 'saveHighlight':
        requireAdmin(auth);
        return jsonResponse(handleSaveHighlight(params));
      case 'deleteHighlight':
        requireAdmin(auth);
        return jsonResponse(handleDeleteHighlight(params.rowIndex));
      case 'sendManualNotification':
        requireAdmin(auth);
        return jsonResponse(handleManualNotification(params));
      case 'runHealthCheck':
        requireAdmin(auth);
        return jsonResponse(repairAndSyncSheet());
      default:
        return jsonResponse({ success: false, error: 'Unknown action: ' + action });
    }
  } catch (err) {
    return jsonResponse({
      success: false,
      error: err.message || String(err)
    });
  }
}

function jsonResponse(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// ─── 3. CRYPTOGRAPHIC TOKEN & AUTH ENGINE ──────────────────────────────────

function createToken(payloadObj) {
  const data = Object.assign({}, payloadObj, {
    exp: Date.now() + (1000 * 60 * 60 * 24 * 7) // 7-day validity
  });
  const base64Payload = Utilities.base64EncodeWebSafe(JSON.stringify(data));
  const signatureBytes = Utilities.computeHmacSha256Signature(base64Payload, TOKEN_SECRET);
  const base64Sig = Utilities.base64EncodeWebSafe(signatureBytes);
  return base64Payload + '.' + base64Sig;
}

function verifyToken(tokenStr) {
  if (!tokenStr || typeof tokenStr !== 'string' || !tokenStr.includes('.')) {
    return { valid: false };
  }
  try {
    const parts = tokenStr.split('.');
    const base64Payload = parts[0];
    const providedSig = parts[1];
    const expectedBytes = Utilities.computeHmacSha256Signature(base64Payload, TOKEN_SECRET);
    const expectedSig = Utilities.base64EncodeWebSafe(expectedBytes);
    if (providedSig !== expectedSig) return { valid: false };

    const jsonStr = Utilities.newBlob(Utilities.base64DecodeWebSafe(base64Payload)).getDataAsString();
    const payload = JSON.parse(jsonStr);
    if (!payload.exp || Date.now() > payload.exp) {
      return { valid: false, expired: true };
    }
    return { valid: true, user: payload };
  } catch (e) {
    return { valid: false };
  }
}

function requireAdmin(auth) {
  if (!auth || !auth.valid || !auth.user || auth.user.role !== 'admin') {
    throw new Error('Admin privileges required for this action.');
  }
}

// ─── 4. SHEET INITIALIZATION & AUTOMATED REPAIR ENGINE ────────────────────

/**
 * Run this once manually in Apps Script Editor if starting a blank sheet.
 */
function setupSheet() {
  const ss = getSpreadsheet();
  const schema = {
    [TABS.ORDERS]: [
      'Timestamp', 'OrderNo', 'OrderedPlatform', 'AccountName', 'ProductName',
      'SellerName', 'ProductLink', 'PlatformOrderID', 'PricePaid', 'Less',
      'DealContactNo', 'MediatorName', 'OrderDate', 'ForWhom', 'UserID',
      'BuyerLess', 'Notes', 'MediatorOrderForm', 'MediatorRefundForm',
      'OrderScreenshot', 'Remarks'
    ],
    [TABS.TRACKING]: [
      'OrderNo', 'OrderedPlatform', 'AccountName', 'ProductName', 'PlatformOrderID',
      'PricePaid', 'Less', 'ToGet', 'ActualGot', 'OrderStatus',
      'OrderDate', 'DeliveryDate', 'ReviewDate', 'ReviewLiveDate', 'RefundFormDate',
      'RefundDate', 'MediatorName', 'BuyerToget', 'BuyerActualGot', 'PaymentMethod',
      'PaymentStatus', 'PaymentDate', 'UserID', 'BuyerLess', 'ForWhom',
      'Notes', 'ReviewLink', 'OrderScreenshot'
    ],
    [TABS.ACCOUNTS]: [
      'UserID', 'Name', 'Account_Type', 'Mobile', 'WhatsApp',
      'Parent_UserID', 'Email', 'Role', 'Password', 'Profile link'
    ],
    [TABS.MEDIATOR]: ['Name', 'Contact', 'WhatsApp', 'Password'],
    [TABS.PLATFORM]: ['Platform', 'OrderStatus', 'DealContactNo'],
    [TABS.DEALS]: [
      'Deal_id', 'title', 'platform', 'product_url', 'price',
      'Less_amount', 'instructions', 'image_url', 'status', 'created_at'
    ],
    [TABS.DEAL_REQUESTS]: [
      'RequestId', 'BuyerName', 'BuyerMobile', 'DealTitle', 'DealId', 'Timestamp', 'Status'
    ],
    [TABS.DASHBOARD]: ['Metric', 'Value'],
    [TABS.INSTRUCTIONS]: ['SastaDeal - Instructions']
  };

  Object.keys(schema).forEach(tabName => {
    let sheet = ss.getSheetByName(tabName);
    if (!sheet) {
      sheet = ss.insertSheet(tabName);
      sheet.appendRow(schema[tabName]);
      sheet.getRange(1, 1, 1, schema[tabName].length).setFontWeight('bold');
    }
  });
  return { success: true, message: 'All tabs verified/created successfully.' };
}

/**
 * Run this function in Apps Script Editor (or via Admin Panel "Data Health Check")
 * to fix your existing SastaDeals sheet:
 * 1. Moves ghost rows at row 2277 up to the real end of Orders/Tracking.
 * 2. Fixes broken #REF! in Tracking!Z2 by syncing Notes to Orders!Q.
 * 3. Fills missing ToGet (=F+G) and BuyerToget (=F-X) formulas.
 * 4. Adds any Mediators present in Orders but missing in Mediator tab.
 */
function repairAndSyncSheet() {
  const ss = getSpreadsheet();
  const ordersSheet = ss.getSheetByName(TABS.ORDERS);
  const trackingSheet = ss.getSheetByName(TABS.TRACKING);
  const medSheet = ss.getSheetByName(TABS.MEDIATOR);

  const report = {
    ghostRowsFixed: 0,
    formulasRestored: 0,
    mediatorsSynced: 0,
    notesSynced: 0
  };

  // 1. Check Orders real last row
  const ordersData = ordersSheet.getDataRange().getValues();
  const realOrderCount = ordersData.length - 1; // excluding header

  // 2. Check Tracking for hardcoded notes in Column Z that break ArrayFormula Z2
  const trackFormulas = trackingSheet.getRange(2, 26, realOrderCount, 1).getFormulas();
  const trackVals = trackingSheet.getRange(2, 26, realOrderCount, 1).getValues();
  for (let i = 0; i < realOrderCount; i++) {
    const cellVal = String(trackVals[i][0] || '').trim();
    const cellFormula = String(trackFormulas[i][0] || '').trim();
    if (i > 0 && cellVal && cellVal !== '#REF!' && !cellFormula) {
      // Move manual note to Orders!Q (col 17) so Tracking!Z2 ArrayFormula works cleanly
      const existingOrderNote = String(ordersSheet.getRange(i + 2, 17).getValue() || '').trim();
      if (!existingOrderNote) {
        ordersSheet.getRange(i + 2, 17).setValue(cellVal);
      }
      trackingSheet.getRange(i + 2, 26).clearContent();
      report.notesSynced++;
    }
  }

  // 3. Rescue any ghost rows at bottom of Tracking (beyond realOrderCount + 1)
  const trackMaxRow = trackingSheet.getLastRow();
  if (trackMaxRow > realOrderCount + 1) {
    for (let r = realOrderCount + 2; r <= trackMaxRow; r++) {
      const rowVals = trackingSheet.getRange(r, 1, 1, 28).getValues()[0];
      const hasData = rowVals.some(v => v !== '' && v !== null);
      if (hasData) {
        // Check if this PlatformOrderID already exists in Orders
        const pId = String(rowVals[4] || '').trim();
        const existsInOrders = ordersData.slice(1).some(o => String(o[7] || '').trim() === pId && pId !== '');
        if (!existsInOrders && pId) {
          const newOrderNo = getNextOrderNo(ordersData);
          const nextOrderRow = ordersSheet.getLastRow() + 1;
          const newOrderRow = [
            new Date(),           // A: Timestamp
            newOrderNo,           // B: OrderNo
            rowVals[1] || '',     // C: OrderedPlatform
            rowVals[2] || '',     // D: AccountName
            rowVals[3] || '',     // E: ProductName
            '',                   // F: SellerName
            '',                   // G: ProductLink
            pId,                  // H: PlatformOrderID
            Number(rowVals[5]) || 0, // I: PricePaid
            Number(rowVals[6]) || 0, // J: Less
            '',                   // K: DealContactNo
            rowVals[16] || '',    // L: MediatorName
            rowVals[10] || new Date(), // M: OrderDate
            rowVals[24] || 'Self',// N: ForWhom
            rowVals[22] || '',    // O: UserID
            Number(rowVals[23]) || 0, // P: BuyerLess
            rowVals[25] || '',    // Q: Notes
            '',                   // R: MediatorOrderForm
            '',                   // S: MediatorRefundForm
            rowVals[27] || '',    // T: OrderScreenshot
            ''                    // U: Remarks
          ];
          ordersSheet.getRange(nextOrderRow, 1, 1, 21).setValues([newOrderRow]);
          // Copy tracking specifics to nextOrderRow in Tracking
          trackingSheet.getRange(nextOrderRow, 8).setFormula(`=F${nextOrderRow}+G${nextOrderRow}`);
          trackingSheet.getRange(nextOrderRow, 9, 1, 2).setValues([[rowVals[8] || '', rowVals[9] || 'Order Placed']]);
          trackingSheet.getRange(nextOrderRow, 12, 1, 5).setValues([[rowVals[11]||'', rowVals[12]||'', rowVals[13]||'', rowVals[14]||'', rowVals[15]||'']]);
          trackingSheet.getRange(nextOrderRow, 18).setFormula(`=F${nextOrderRow}-X${nextOrderRow}`);
          trackingSheet.getRange(nextOrderRow, 19, 1, 4).setValues([[rowVals[18]||'', rowVals[19]||'', rowVals[20]||'', rowVals[21]||'']]);
          report.ghostRowsFixed++;
        }
        trackingSheet.getRange(r, 1, 1, 28).clearContent();
      }
    }
  }

  // 4. Restore missing ToGet (Col H) and BuyerToget (Col R) formulas in Tracking
  const finalOrderLastRow = ordersSheet.getLastRow();
  const hFormulas = trackingSheet.getRange(2, 8, finalOrderLastRow - 1, 1).getFormulas();
  const rFormulas = trackingSheet.getRange(2, 18, finalOrderLastRow - 1, 1).getFormulas();
  for (let i = 0; i < finalOrderLastRow - 1; i++) {
    const rowNum = i + 2;
    if (!hFormulas[i][0]) {
      trackingSheet.getRange(rowNum, 8).setFormula(`=F${rowNum}+G${rowNum}`);
      report.formulasRestored++;
    }
    if (!rFormulas[i][0]) {
      trackingSheet.getRange(rowNum, 18).setFormula(`=F${rowNum}-X${rowNum}`);
      report.formulasRestored++;
    }
  }

  // 5. Sync missing Mediators from Orders into Mediator sheet
  if (medSheet) {
    const medData = medSheet.getDataRange().getValues();
    const existingMeds = new Set(medData.slice(1).map(r => String(r[0] || '').trim().toLowerCase()).filter(Boolean));
    const freshOrders = ordersSheet.getDataRange().getValues();
    freshOrders.slice(1).forEach(r => {
      const mName = String(r[11] || '').trim();
      if (mName && mName.toLowerCase() !== 'self' && !existingMeds.has(mName.toLowerCase())) {
        medSheet.appendRow([mName, '', '91', '123456']);
        existingMeds.add(mName.toLowerCase());
        report.mediatorsSynced++;
      }
    });
  }

  SpreadsheetApp.flush();
  return {
    success: true,
    message: `Sheet health check complete! Fixed ${report.ghostRowsFixed} ghost rows, restored ${report.formulasRestored} formulas, synced ${report.notesSynced} notes, and added ${report.mediatorsSynced} missing mediators.`,
    report: report
  };
}

// ─── 5. DATA MERGE & MATH NORMALIZATION ENGINE ────────────────────────────

function getSpreadsheet() {
  if (SHEET_ID && SHEET_ID !== 'YOUR_GOOGLE_SHEET_ID_HERE') {
    return SpreadsheetApp.openById(SHEET_ID);
  }
  return SpreadsheetApp.getActiveSpreadsheet();
}

/**
 * Finds the true last row in a sheet based on a specific column (1-based)
 * so ArrayFormulas don't trick getLastRow() into returning Row 2277.
 */
function getRealLastRow(sheet, colIndex) {
  const vals = sheet.getRange(1, colIndex, Math.max(sheet.getLastRow(), 2), 1).getValues();
  for (let i = vals.length - 1; i >= 1; i--) {
    const v = vals[i][0];
    if (v !== '' && v !== null && v !== undefined) {
      return i + 1;
    }
  }
  return 1;
}

function getNextOrderNo(ordersValues) {
  let maxNo = 0;
  for (let i = 1; i < ordersValues.length; i++) {
    const n = Number(ordersValues[i][1]);
    if (!isNaN(n) && n > maxNo) maxNo = n;
  }
  return maxNo + 1;
}

/**
 * Normalizes Mediator ToGet and Buyer ToGet accurately across historical rows.
 * - In SastaDeals, Mediator `Less` (Col J in Orders / Col G in Tracking) has negative values (-249)
 *   for deductions and positive (+120) for commission. Sheet formula is `PricePaid + Less`.
 * - `BuyerLess` (Col P in Orders / Col X in Tracking) is positive (200) for deduction.
 *   Sheet formula is `PricePaid - BuyerLess`.
 */
function computeFinancials(pricePaid, medLess, buyerLess, sheetToGet, sheetBuyerToGet) {
  const price = parseNum(pricePaid);
  const less = parseNum(medLess);
  const bLess = parseNum(buyerLess);

  let toGet = parseNum(sheetToGet, null);
  if (toGet === null || isNaN(toGet)) {
    toGet = price + less;
  }

  let buyerToGet = parseNum(sheetBuyerToGet, null);
  if (buyerToGet === null || isNaN(buyerToGet)) {
    buyerToGet = price - Math.abs(bLess);
  }

  return {
    pricePaid: price,
    less: less,
    buyerLess: Math.abs(bLess),
    toGet: round2(toGet),
    buyerToGet: round2(buyerToGet)
  };
}

function parseNum(val, fallback = 0) {
  if (val === '' || val === null || val === undefined) return fallback;
  const cleaned = String(val).replace(/[^\d.-]/g, '');
  const n = parseFloat(cleaned);
  return isNaN(n) ? fallback : n;
}

function round2(n) {
  return Math.round((Number(n) + Number.EPSILON) * 100) / 100;
}

function formatDateISO(val) {
  if (!val) return '';
  if (Object.prototype.toString.call(val) === '[object Date]') {
    if (isNaN(val.getTime())) return '';
    return Utilities.formatDate(val, Session.getScriptTimeZone() || 'Asia/Kolkata', 'yyyy-MM-dd');
  }
  const str = String(val).trim();
  if (!str || str.startsWith('#')) return '';
  const d = new Date(str);
  if (!isNaN(d.getTime()) && str.length >= 8) {
    return Utilities.formatDate(d, Session.getScriptTimeZone() || 'Asia/Kolkata', 'yyyy-MM-dd');
  }
  return str;
}

/**
 * Merges `Orders` and `Tracking` by row index / OrderNo into clean unified objects.
 */
function getMergedOrders() {
  const ss = getSpreadsheet();
  const ordersSheet = ss.getSheetByName(TABS.ORDERS);
  const trackingSheet = ss.getSheetByName(TABS.TRACKING);

  const ordersData = ordersSheet ? ordersSheet.getDataRange().getValues() : [];
  const trackingData = trackingSheet ? trackingSheet.getDataRange().getValues() : [];

  // Index Tracking rows by OrderNo AND PlatformOrderID for fast O(1) lookup
  const trackByOrderNo = new Map();
  const trackByPlatformId = new Map();

  for (let i = 1; i < trackingData.length; i++) {
    const tRow = trackingData[i];
    const tOrderNo = String(tRow[0] || '').trim();
    const tPlatId = String(tRow[4] || '').trim();
    if (!tOrderNo && !tPlatId) continue;

    const record = { rowIndex: i + 1, data: tRow };
    if (tOrderNo) trackByOrderNo.set(tOrderNo, record);
    if (tPlatId) trackByPlatformId.set(tPlatId.toLowerCase(), record);
  }

  const merged = [];

  for (let i = 1; i < ordersData.length; i++) {
    const o = ordersData[i];
    const orderNo = o[1];
    if (orderNo === '' || orderNo === null || orderNo === undefined) continue;

    const orderNoKey = String(orderNo).trim();
    const platIdKey = String(o[7] || '').trim();

    let tRec = trackByOrderNo.get(orderNoKey) ||
               trackByOrderNo.get(String(Number(orderNoKey))) ||
               (platIdKey ? trackByPlatformId.get(platIdKey.toLowerCase()) : null);

    const t = tRec ? tRec.data : [];
    const trackRowIndex = tRec ? tRec.rowIndex : (i + 1);

    const fin = computeFinancials(o[8], o[9], o[15], t[7], t[17]);
    const actualGot = t[8] !== '' && t[8] !== null && t[8] !== undefined ? parseNum(t[8], null) : null;
    const buyerActualGot = t[18] !== '' && t[18] !== null && t[18] !== undefined ? parseNum(t[18], null) : null;

    const rawStatus = String(t[9] || 'Order Placed').trim();
    const rawPayStatus = String(t[20] || '').trim();

    const cleanNote = (String(o[16] || '').trim() && !String(o[16]).startsWith('#'))
      ? String(o[16]).trim()
      : (String(t[25] || '').trim() && !String(t[25]).startsWith('#') ? String(t[25]).trim() : '');

    merged.push({
      orderRowIndex:      i + 1,
      trackRowIndex:      trackRowIndex,
      timestamp:          formatDateISO(o[0]),
      orderNo:            Number(orderNo) || orderNoKey,
      orderedPlatform:    String(o[2] || t[1] || '').trim(),
      accountName:        String(o[3] || t[2] || '').trim(),
      productName:        String(o[4] || t[3] || '').trim(),
      sellerName:         String(o[5] || '').trim(),
      productLink:        String(o[6] || '').trim(),
      platformOrderId:    platIdKey || String(t[4] || '').trim(),
      pricePaid:          fin.pricePaid,
      less:               fin.less,
      dealContactNo:      String(o[10] || '').trim(),
      mediatorName:       String(o[11] || t[16] || '').trim(),
      orderDate:          formatDateISO(o[12] || t[10]),
      forWhom:            String(o[13] || t[24] || 'Self').trim(),
      userId:             String(o[14] || t[22] || '').trim(),
      buyerLess:          fin.buyerLess,
      notes:              cleanNote,
      mediatorOrderForm:  String(o[17] || '').trim(),
      mediatorRefundForm: String(o[18] || '').trim(),
      orderScreenshot:    String(o[19] || t[27] || '').trim(),
      remarks:            String(o[20] || '').trim(),

      // Tracking-specific fields
      toGet:              fin.toGet,
      actualGot:          actualGot,
      orderStatus:        rawStatus || 'Order Placed',
      deliveryDate:       formatDateISO(t[11]),
      reviewDate:         formatDateISO(t[12]),
      reviewLiveDate:     formatDateISO(t[13]),
      refundFormDate:     formatDateISO(t[14]),
      refundDate:         formatDateISO(t[15]),
      buyerToGet:         fin.buyerToGet,
      buyerActualGot:     buyerActualGot,
      paymentMethod:      String(t[19] || '').trim(),
      paymentStatus:      rawPayStatus || 'Pending',
      paymentDate:        formatDateISO(t[21]),
      reviewLink:         String(t[26] || '').trim()
    });
  }

  // Descending order by OrderNo (Key Business Rule #6)
  merged.sort((a, b) => (Number(b.orderNo) || 0) - (Number(a.orderNo) || 0));
  return merged;
}

// ─── 6. PUBLIC ENDPOINTS (HOMEPAGE, TRACKING, DEALS) ──────────────────────

function getPublicHomeData() {
  const orders = getMergedOrders();
  const todayStr = formatDateISO(new Date());

  let totalOrders = orders.length;
  let totalRefundAmount = 0;
  let pendingCount = 0;
  let todayCount = 0;

  orders.forEach(o => {
    const isRefunded = o.orderStatus.toLowerCase() === 'got refund';
    if (isRefunded) {
      totalRefundAmount += (o.actualGot !== null ? o.actualGot : o.toGet);
    } else if (!o.orderStatus.toLowerCase().includes('cancel')) {
      pendingCount++;
    }
    if (o.orderDate === todayStr) {
      todayCount++;
    }
  });

  const highlights = getHighlightsList('public');
  const dealsResp = getDealsList(null);

  return {
    success: true,
    stats: {
      totalOrders: totalOrders,
      totalRefund: round2(totalRefundAmount),
      pendingOrders: pendingCount,
      todayOrders: todayCount
    },
    highlights: highlights,
    featuredDeals: (dealsResp.deals || []).slice(0, 6)
  };
}

/**
 * Key Business Rule #7: Track page ONLY accepts PlatformOrderID (NOT OrderNo).
 * Strips MediatorName, SellerName, and Mediator Less.
 */
function trackOrderByPlatformID(platformOrderId) {
  const query = String(platformOrderId || '').trim();
  if (!query) {
    return { success: false, error: 'Please enter a valid Platform Order ID (e.g., 404-2759471-7602761).' };
  }

  // Reject purely short numeric OrderNo queries (e.g. "1", "1195")
  if (/^\d{1,6}$/.test(query)) {
    return {
      success: false,
      error: 'Please track using your Platform Order ID (from Amazon/Flipkart/Blinkit), not the serial Order No.'
    };
  }

  const orders = getMergedOrders();
  const match = orders.find(o => o.platformOrderId.toLowerCase() === query.toLowerCase());

  if (!match) {
    return { success: false, error: 'No order found with Platform Order ID: ' + query };
  }

  return {
    success: true,
    order: {
      orderNo:         match.orderNo,
      orderedPlatform: match.orderedPlatform,
      accountName:     match.accountName,
      productName:     match.productName,
      platformOrderId: match.platformOrderId,
      pricePaid:       match.pricePaid,
      buyerLess:       match.buyerLess,
      buyerToGet:      match.buyerToGet,
      buyerActualGot:  match.buyerActualGot,
      orderStatus:     match.orderStatus,
      orderDate:       match.orderDate,
      deliveryDate:    match.deliveryDate,
      reviewDate:      match.reviewDate,
      reviewLiveDate:  match.reviewLiveDate,
      refundFormDate:  match.refundFormDate,
      refundDate:      match.refundDate,
      paymentStatus:   match.paymentStatus,
      paymentMethod:   match.paymentMethod,
      paymentDate:     match.paymentDate,
      reviewLink:      match.reviewLink,
      orderScreenshot: match.orderScreenshot
    }
  };
}

function getDealsList(tokenStr) {
  const auth = verifyToken(tokenStr);
  const isLoggedIn = auth.valid;

  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.DEALS);
  if (!sheet) return { success: true, deals: [], isLoggedIn: isLoggedIn };

  const rows = sheet.getDataRange().getValues();
  const deals = [];

  for (let i = 1; i < rows.length; i++) {
    const r = rows[i];
    if (!r[0] && !r[1]) continue;
    const status = String(r[8] || 'active').trim().toLowerCase();
    if (!isLoggedIn && status !== 'active') continue;

    const price = parseNum(r[4]);
    const lessAmount = parseNum(r[5]);
    const youGet = round2(price - Math.abs(lessAmount));

    deals.push({
      rowIndex:     i + 1,
      dealId:       String(r[0] || '').trim(),
      title:        String(r[1] || '').trim(),
      platform:     String(r[2] || 'Amazon').trim(),
      productUrl:   isLoggedIn ? String(r[3] || '').trim() : '',
      price:        isLoggedIn ? price : null,
      lessAmount:   isLoggedIn ? Math.abs(lessAmount) : null,
      youGet:       isLoggedIn ? youGet : null,
      instructions: String(r[6] || '').trim(),
      imageUrl:     String(r[7] || '').trim(),
      status:       status,
      createdAt:    formatDateISO(r[9])
    });
  }

  deals.reverse();
  return { success: true, deals: deals, isLoggedIn: isLoggedIn };
}

// ─── 7. AUTHENTICATION (LOGIN, REGISTER, FORGOT PASSWORD) ─────────────────

function handleLogin(params) {
  const role = String(params.role || 'buyer').trim().toLowerCase();
  const identifier = String(params.identifier || '').trim();
  const password = String(params.password || '').trim();

  if (!password) {
    return { success: false, error: 'Password is required.' };
  }

  // 1. Admin Login
  if (role === 'admin') {
    if (password === ADMIN_PASSWORD) {
      const userObj = {
        role: 'admin',
        userId: 'ADMIN',
        name: 'Sanjeet (Admin)',
        mobile: ADMIN_WHATSAPP
      };
      return {
        success: true,
        token: createToken(userObj),
        user: userObj
      };
    }
    return { success: false, error: 'Incorrect Admin password.' };
  }

  const ss = getSpreadsheet();
  const accSheet = ss.getSheetByName(TABS.ACCOUNTS);
  const accRows = accSheet ? accSheet.getDataRange().getValues() : [];

  const cleanId = identifier.toLowerCase();
  const cleanPhone = identifier.replace(/\D/g, '').slice(-10);

  // 2. Buyer Login
  if (role === 'buyer') {
    if (!identifier) return { success: false, error: 'Please enter your Mobile, Email, or UserID.' };

    let matchedRow = null;
    for (let i = 1; i < accRows.length; i++) {
      const r = accRows[i];
      const rRole = String(r[7] || 'buyer').trim().toLowerCase();
      if (rRole !== 'buyer') continue;

      const rUid = String(r[0] || '').trim().toLowerCase();
      const rName = String(r[1] || '').trim().toLowerCase();
      const rMob = String(r[3] || '').replace(/\D/g, '').slice(-10);
      const rWa = String(r[4] || '').replace(/\D/g, '').slice(-10);
      const rParent = String(r[5] || '').trim().toLowerCase();
      const rEmail = String(r[6] || '').trim().toLowerCase();
      const rPass = String(r[8] || '').trim();

      const idMatch = (cleanId && (rUid === cleanId || rEmail === cleanId || rParent === cleanId || rName === cleanId)) ||
                      (cleanPhone.length === 10 && (rMob === cleanPhone || rWa === cleanPhone));

      if (idMatch && rPass === password) {
        matchedRow = r;
        // Prefer Main account if multiple sub-accounts share the same mobile/password
        if (String(r[2] || '').trim().toLowerCase() === 'main') break;
      }
    }

    if (!matchedRow) {
      return { success: false, error: 'Invalid Buyer credentials. Check your Mobile/UserID and password.' };
    }

    // Resolve Parent Name & Linked Sub-Accounts
    const parentId = String(matchedRow[5] || matchedRow[0] || '').trim();
    const userMob = String(matchedRow[3] || '').replace(/\D/g, '').slice(-10);
    let parentName = String(matchedRow[1] || '').trim();

    for (let i = 1; i < accRows.length; i++) {
      const r = accRows[i];
      if (String(r[0] || '').trim().toLowerCase() === parentId.toLowerCase()) {
        parentName = String(r[1] || parentName).trim();
        break;
      }
    }

    const userObj = {
      role: 'buyer',
      userId: String(matchedRow[0] || '').trim(),
      name: String(matchedRow[1] || '').trim(),
      accountType: String(matchedRow[2] || 'Main').trim(),
      mobile: userMob,
      whatsApp: String(matchedRow[4] || '').trim(),
      parentUserId: parentId,
      parentName: parentName,
      email: String(matchedRow[6] || '').trim()
    };

    return {
      success: true,
      token: createToken(userObj),
      user: userObj
    };
  }

  // 3. Mediator Login (Checks both Accounts[role=mediator] and Mediator tab)
  if (role === 'mediator') {
    if (!identifier) return { success: false, error: 'Please enter your Mediator Name, Mobile, or Email.' };

    // Check Accounts sheet first
    for (let i = 1; i < accRows.length; i++) {
      const r = accRows[i];
      if (String(r[7] || '').trim().toLowerCase() !== 'mediator') continue;

      const rUid = String(r[0] || '').trim().toLowerCase();
      const rName = String(r[1] || '').trim().toLowerCase();
      const rMob = String(r[3] || '').replace(/\D/g, '').slice(-10);
      const rEmail = String(r[6] || '').trim().toLowerCase();
      const rPass = String(r[8] || '').trim();

      const idMatch = (cleanId && (rUid === cleanId || rName === cleanId || rEmail === cleanId)) ||
                      (cleanPhone.length === 10 && rMob === cleanPhone);

      if (idMatch && rPass === password) {
        const userObj = {
          role: 'mediator',
          userId: String(r[0] || r[1]).trim(),
          name: String(r[1] || '').trim(),
          mobile: rMob,
          email: String(r[6] || '').trim()
        };
        return { success: true, token: createToken(userObj), user: userObj };
      }
    }

    // Check Mediator sheet
    const medSheet = ss.getSheetByName(TABS.MEDIATOR);
    const medRows = medSheet ? medSheet.getDataRange().getValues() : [];
    for (let i = 1; i < medRows.length; i++) {
      const m = medRows[i];
      const mName = String(m[0] || '').trim();
      const mContact = String(m[1] || '').replace(/\D/g, '').slice(-10);
      const mWa = String(m[2] || '').replace(/\D/g, '').slice(-10);
      const mPass = String(m[3] || '123456').trim();

      const idMatch = (cleanId && mName.toLowerCase() === cleanId) ||
                      (cleanPhone.length === 10 && (mContact === cleanPhone || mWa === cleanPhone));

      if (idMatch && mPass === password) {
        const userObj = {
          role: 'mediator',
          userId: mName,
          name: mName,
          mobile: mContact || mWa
        };
        return { success: true, token: createToken(userObj), user: userObj };
      }
    }

    return { success: false, error: 'Invalid Mediator credentials.' };
  }

  return { success: false, error: 'Unsupported login role.' };
}

function handleRegisterAccount(params) {
  const role = String(params.role || 'buyer').trim().toLowerCase();
  const name = String(params.name || '').trim();
  const mobile = String(params.mobile || '').replace(/\D/g, '').slice(-10);
  const email = String(params.email || '').trim();
  const password = String(params.password || '').trim();
  const profileLink = String(params.profileLink || '').trim();

  if (!name || mobile.length !== 10 || !password) {
    return { success: false, error: 'Name, 10-digit Mobile Number, and Password are required.' };
  }

  const ss = getSpreadsheet();
  const accSheet = ss.getSheetByName(TABS.ACCOUNTS);
  const rows = accSheet.getDataRange().getValues();

  // Check if mobile or name already registered for this role
  for (let i = 1; i < rows.length; i++) {
    const rMob = String(rows[i][3] || '').replace(/\D/g, '').slice(-10);
    const rRole = String(rows[i][7] || '').trim().toLowerCase();
    if (rMob === mobile && rRole === role) {
      return { success: false, error: 'An account with this mobile number already exists. Please login.' };
    }
  }

  const prefix = role === 'mediator' ? 'MED_' : 'B_';
  const cleanFirst = name.replace(/[^a-zA-Z0-9]/g, '').slice(0, 6) || 'User';
  const userId = `${prefix}${cleanFirst}_${mobile.slice(-3)}`;

  accSheet.appendRow([
    userId,
    name,
    role === 'mediator' ? 'mediator' : 'Main',
    mobile,
    '91' + mobile,
    role === 'mediator' ? '' : userId,
    email,
    role,
    password,
    profileLink
  ]);

  if (role === 'mediator') {
    const medSheet = ss.getSheetByName(TABS.MEDIATOR);
    if (medSheet) {
      medSheet.appendRow([name, mobile, '91' + mobile, password]);
    }
  }

  return {
    success: true,
    message: `Account created! Your UserID is ${userId}. You can now login with your mobile number or UserID.`
  };
}

function handleForgotPassword(params) {
  const identifier = String(params.identifier || '').trim().toLowerCase();
  const mobile = identifier.replace(/\D/g, '').slice(-10);
  if (!identifier) return { success: false, error: 'Please enter your registered Mobile or Email.' };

  const ss = getSpreadsheet();
  const accSheet = ss.getSheetByName(TABS.ACCOUNTS);
  const rows = accSheet.getDataRange().getValues();

  for (let i = 1; i < rows.length; i++) {
    const r = rows[i];
    const rUid = String(r[0] || '').trim().toLowerCase();
    const rName = String(r[1] || '').trim();
    const rMob = String(r[3] || '').replace(/\D/g, '').slice(-10);
    const rEmail = String(r[6] || '').trim().toLowerCase();
    const rPass = String(r[8] || '').trim();

    if ((mobile.length === 10 && rMob === mobile) || rEmail === identifier || rUid === identifier) {
      if (rEmail && rEmail.includes('@')) {
        sendEmailSafe(
          rEmail,
          'SastaDeal — Password Recovery',
          `Hello ${rName},\n\nYour SastaDeal login details:\nUserID: ${r[0]}\nMobile: ${rMob}\nPassword: ${rPass}\n\nLogin at SastaDeal Dashboard.`
        );
        return { success: true, message: `Password has been sent to your registered email (${rEmail}).` };
      } else {
        // Notify Admin on WhatsApp to assist buyer
        sendCallMeBotWhatsApp(`🔑 *Password Reset Request*\nName: ${rName}\nUserID: ${r[0]}\nMobile: ${rMob}\nCurrent Password: ${rPass}`);
        return {
          success: true,
          message: 'Admin has been notified on WhatsApp with your credentials and will message you shortly.'
        };
      }
    }
  }
  return { success: false, error: 'No matching account found with that Mobile, Email, or UserID.' };
}

// ─── 8. ROLE-BASED DASHBOARD DATA ENGINE ──────────────────────────────────

function getDashboardDataForRole(auth, params) {
  const role = auth.user.role;
  const allOrders = getMergedOrders();
  const ss = getSpreadsheet();

  // Read Accounts
  const accSheet = ss.getSheetByName(TABS.ACCOUNTS);
  const accRows = accSheet ? accSheet.getDataRange().getValues() : [];
  const accountsList = [];
  for (let i = 1; i < accRows.length; i++) {
    const r = accRows[i];
    if (!r[0] && !r[1]) continue;
    accountsList.push({
      rowIndex:     i + 1,
      userId:       String(r[0] || '').trim(),
      name:         String(r[1] || '').trim(),
      accountType:  String(r[2] || '').trim(),
      mobile:       String(r[3] || '').replace(/\.0$/, '').trim(),
      whatsApp:     String(r[4] || '').replace(/\.0$/, '').trim(),
      parentUserId: String(r[5] || '').trim(),
      email:        String(r[6] || '').trim(),
      role:         String(r[7] || 'buyer').trim().toLowerCase(),
      password:     role === 'admin' ? String(r[8] || '').trim() : undefined,
      profileLink:  String(r[9] || '').trim()
    });
  }

  // Read Platform dropdowns
  const platSheet = ss.getSheetByName(TABS.PLATFORM);
  const platRows = platSheet ? platSheet.getDataRange().getValues() : [];
  const platforms = [];
  const statuses = [];
  const dealContacts = [];
  for (let i = 1; i < platRows.length; i++) {
    const p = String(platRows[i][0] || '').trim();
    const s = String(platRows[i][1] || '').trim();
    const c = String(platRows[i][2] || '').replace(/\.0$/, '').trim();
    if (p && !platforms.includes(p)) platforms.push(p);
    if (s && !statuses.includes(s)) statuses.push(s);
    if (c && !dealContacts.includes(c)) dealContacts.push(c);
  }

  // ── A. BUYER DASHBOARD PAYLOAD ──
  if (role === 'buyer') {
    const myUserId = String(auth.user.userId || '').toLowerCase();
    const myParentId = String(auth.user.parentUserId || myUserId).toLowerCase();
    const myMobile = String(auth.user.mobile || '').replace(/\D/g, '').slice(-10);

    // Find all UserIDs belonging to this buyer's family (Parent_UserID / Mobile / Email)
    const linkedAccounts = accountsList.filter(a => {
      if (a.role !== 'buyer') return false;
      const aUid = a.userId.toLowerCase();
      const aParent = a.parentUserId.toLowerCase();
      const aMob = a.mobile.replace(/\D/g, '').slice(-10);
      return (
        aUid === myUserId ||
        (myParentId && (aParent === myParentId || aUid === myParentId)) ||
        (myMobile.length === 10 && aMob === myMobile)
      );
    });

    const allowedUserIds = new Set(linkedAccounts.map(a => a.userId.toLowerCase()));
    allowedUserIds.add(myUserId);
    if (myParentId) allowedUserIds.add(myParentId);

    // Filter orders strictly to Buyer's linked accounts AND strip Mediator secrets
    const buyerOrders = allOrders
      .filter(o => allowedUserIds.has(String(o.userId || '').toLowerCase()))
      .map(o => ({
        orderNo:            o.orderNo,
        orderedPlatform:    o.orderedPlatform,
        accountName:        o.accountName,
        productName:        o.productName,
        productLink:        o.productLink,
        platformOrderId:    o.platformOrderId,
        pricePaid:          o.pricePaid,
        buyerLess:          o.buyerLess,
        buyerToGet:         o.buyerToGet,
        buyerActualGot:     o.buyerActualGot,
        orderStatus:        o.orderStatus,
        orderDate:          o.orderDate,
        deliveryDate:       o.deliveryDate,
        reviewDate:         o.reviewDate,
        reviewLiveDate:     o.reviewLiveDate,
        refundFormDate:     o.refundFormDate,
        refundDate:         o.refundDate,
        paymentMethod:      o.paymentMethod,
        paymentStatus:      o.paymentStatus,
        paymentDate:        o.paymentDate,
        userId:             o.userId,
        forWhom:            o.forWhom,
        notes:              o.notes,
        reviewLink:         o.reviewLink,
        orderScreenshot:    o.orderScreenshot
      }));

    return {
      success: true,
      role: 'buyer',
      user: auth.user,
      linkedAccounts: linkedAccounts.map(a => ({
        userId: a.userId,
        name: a.name,
        accountType: a.accountType,
        parentUserId: a.parentUserId,
        profileLink: a.profileLink
      })),
      orders: buyerOrders,
      deals: getDealsList(params.token).deals,
      highlights: getHighlightsList('buyer'),
      dropdowns: { platforms, statuses, dealContacts }
    };
  }

  // ── B. MEDIATOR DASHBOARD PAYLOAD ──
  if (role === 'mediator') {
    const medName = String(auth.user.name || '').trim().toLowerCase();
    const medOrders = allOrders
      .filter(o => String(o.mediatorName || '').trim().toLowerCase() === medName)
      .map(o => ({
        orderNo:            o.orderNo,
        orderedPlatform:    o.orderedPlatform,
        accountName:        o.accountName,
        productName:        o.productName,
        sellerName:         o.sellerName,
        platformOrderId:    o.platformOrderId,
        pricePaid:          o.pricePaid,
        less:               o.less,
        toGet:              o.toGet,
        actualGot:          o.actualGot,
        orderStatus:        o.orderStatus,
        orderDate:          o.orderDate,
        deliveryDate:       o.deliveryDate,
        reviewDate:         o.reviewDate,
        reviewLiveDate:     o.reviewLiveDate,
        refundFormDate:     o.refundFormDate,
        refundDate:         o.refundDate,
        mediatorName:       o.mediatorName,
        notes:              o.notes,
        reviewLink:         o.reviewLink,
        orderScreenshot:    o.orderScreenshot
      }));

    return {
      success: true,
      role: 'mediator',
      user: auth.user,
      orders: medOrders,
      highlights: getHighlightsList('mediator'),
      dropdowns: { platforms, statuses }
    };
  }

  // ── C. ADMIN FULL DASHBOARD PAYLOAD ──
  const medSheet = ss.getSheetByName(TABS.MEDIATOR);
  const medRows = medSheet ? medSheet.getDataRange().getValues() : [];
  const mediatorsList = [];
  for (let i = 1; i < medRows.length; i++) {
    const m = medRows[i];
    if (!m[0]) continue;
    mediatorsList.push({
      rowIndex: i + 1,
      name:     String(m[0] || '').trim(),
      contact:  String(m[1] || '').replace(/\.0$/, '').trim(),
      whatsApp: String(m[2] || '').replace(/\.0$/, '').trim(),
      password: String(m[3] || '').trim()
    });
  }

  const reqSheet = ss.getSheetByName(TABS.DEAL_REQUESTS);
  const reqRows = reqSheet ? reqSheet.getDataRange().getValues() : [];
  const dealRequests = [];
  for (let i = 1; i < reqRows.length; i++) {
    const r = reqRows[i];
    if (!r[0]) continue;
    dealRequests.push({
      rowIndex:    i + 1,
      requestId:   String(r[0] || '').trim(),
      buyerName:   String(r[1] || '').trim(),
      buyerMobile: String(r[2] || '').replace(/\.0$/, '').trim(),
      dealTitle:   String(r[3] || '').trim(),
      dealId:      String(r[4] || '').trim(),
      timestamp:   formatDateISO(r[5]),
      status:      String(r[6] || 'pending').trim()
    });
  }
  dealRequests.reverse();

  return {
    success: true,
    role: 'admin',
    user: auth.user,
    orders: allOrders,
    accounts: accountsList,
    mediators: mediatorsList,
    deals: getDealsList(params.token).deals,
    dealRequests: dealRequests,
    highlights: getHighlightsList('admin'),
    dropdowns: { platforms, statuses, dealContacts }
  };
}

// ─── 9. ORDER CRUD, BULK ACTIONS & BATCH SETTLEMENT ──────────────────────

function getOrderByIdentifier(queryStr, auth) {
  const q = String(queryStr || '').trim().toLowerCase();
  if (!q) return { success: false, error: 'Order No or PlatformOrderID is required.' };

  const orders = getMergedOrders();
  const match = orders.find(o =>
    String(o.orderNo).toLowerCase() === q ||
    String(o.platformOrderId || '').toLowerCase() === q
  );

  if (!match) {
    return { success: false, error: 'Order not found for: ' + queryStr };
  }
  return { success: true, order: match };
}

function handleAddOrder(auth, params) {
  const ss = getSpreadsheet();
  const ordersSheet = ss.getSheetByName(TABS.ORDERS);
  const trackingSheet = ss.getSheetByName(TABS.TRACKING);

  const ordersValues = ordersSheet.getDataRange().getValues();
  const newOrderNo = getNextOrderNo(ordersValues);
  const nextRow = getRealLastRow(ordersSheet, 2) + 1;

  const platformOrderId = String(params.platformOrderId || '').trim();
  if (!platformOrderId) {
    return { success: false, error: 'Platform Order ID is required.' };
  }

  // Duplicate check on PlatformOrderID
  const duplicate = ordersValues.slice(1).some(r => String(r[7] || '').trim().toLowerCase() === platformOrderId.toLowerCase());
  if (duplicate) {
    return { success: false, error: `Platform Order ID "${platformOrderId}" already exists in Orders!` };
  }

  const pricePaid = parseNum(params.pricePaid, 0);
  // If buyer submits order, Mediator Less defaults to 0 until Admin sets it
  const less = auth.user.role === 'admin' ? parseNum(params.less, 0) : 0;
  const buyerLess = parseNum(params.buyerLess, 0);
  const orderDate = params.orderDate || formatDateISO(new Date());
  const userId = String(params.userId || auth.user.userId || '').trim();
  const accountName = String(params.accountName || auth.user.name || '').trim();
  const mediatorName = auth.user.role === 'admin' ? String(params.mediatorName || 'Self').trim() : 'Self';

  const newOrderRow = [
    new Date(),                                // A: Timestamp
    newOrderNo,                                // B: OrderNo
    String(params.orderedPlatform || 'Amazon').trim(), // C: OrderedPlatform
    accountName,                               // D: AccountName
    String(params.productName || '').trim(),   // E: ProductName
    String(params.sellerName || '').trim(),    // F: SellerName
    String(params.productLink || '').trim(),   // G: ProductLink
    platformOrderId,                           // H: PlatformOrderID
    pricePaid,                                 // I: PricePaid
    less,                                      // J: Less
    String(params.dealContactNo || '').trim(), // K: DealContactNo
    mediatorName,                              // L: MediatorName
    orderDate,                                 // M: OrderDate
    String(params.forWhom || 'Self').trim(),   // N: ForWhom
    userId,                                    // O: UserID
    buyerLess,                                 // P: BuyerLess
    String(params.notes || '').trim(),         // Q: Notes
    String(params.mediatorOrderForm || '').trim(),  // R: MediatorOrderForm
    String(params.mediatorRefundForm || '').trim(), // S: MediatorRefundForm
    String(params.orderScreenshot || '').trim(),    // T: OrderScreenshot
    String(params.remarks || '').trim()        // U: Remarks
  ];

  // Write to Orders at exact nextRow (prevents ghost row gaps)
  ordersSheet.getRange(nextRow, 1, 1, 21).setValues([newOrderRow]);

  // Write ONLY non-ArrayFormula columns to Tracking at exact nextRow
  // Col H (8): ToGet formula =F{row}+G{row}
  // Col J (10): OrderStatus
  // Col R (18): BuyerToget formula =F{row}-X{row}
  // Col U (21): PaymentStatus
  trackingSheet.getRange(nextRow, 8).setFormula(`=F${nextRow}+G${nextRow}`);
  trackingSheet.getRange(nextRow, 10).setValue(String(params.orderStatus || 'Order Placed').trim());
  trackingSheet.getRange(nextRow, 18).setFormula(`=F${nextRow}-X${nextRow}`);
  trackingSheet.getRange(nextRow, 21).setValue('Pending payment');

  SpreadsheetApp.flush();

  // Trigger Notifications (Trigger #1: Order Submitted)
  const notifyData = {
    orderNo: newOrderNo,
    orderDate: orderDate,
    orderedPlatform: newOrderRow[2],
    accountName: accountName,
    productName: newOrderRow[4],
    productLink: newOrderRow[6],
    platformOrderId: platformOrderId,
    pricePaid: pricePaid,
    buyerLess: buyerLess,
    buyerToGet: round2(pricePaid - Math.abs(buyerLess)),
    userId: userId,
    notes: newOrderRow[16],
    orderScreenshot: newOrderRow[19]
  };
  triggerOrderNotification('ORDER_SUBMITTED', notifyData);

  return {
    success: true,
    orderNo: newOrderNo,
    message: `Order #${newOrderNo} (${platformOrderId}) added successfully!`,
    whatsappReceipt: buildWhatsAppReceiptText('ORDER_SUBMITTED', notifyData)
  };
}

/**
 * ArrayFormula-Safe Full Order Update (Admin)
 */
function handleUpdateOrderFull(params) {
  const orderObj = findOrderRowIndices(params.orderNo, params.platformOrderId);
  if (!orderObj) return { success: false, error: 'Order not found.' };

  const ss = getSpreadsheet();
  const ordersSheet = ss.getSheetByName(TABS.ORDERS);
  const trackingSheet = ss.getSheetByName(TABS.TRACKING);

  const oRow = orderObj.orderRowIndex;
  const tRow = orderObj.trackRowIndex;

  const prevStatus = String(orderObj.orderStatus || '').trim();
  const prevPaymentStatus = String(orderObj.paymentStatus || '').trim();

  // 1. Update shared columns in Orders sheet (Cols C to U)
  if (params.orderedPlatform !== undefined) ordersSheet.getRange(oRow, 3).setValue(params.orderedPlatform);
  if (params.accountName !== undefined)     ordersSheet.getRange(oRow, 4).setValue(params.accountName);
  if (params.productName !== undefined)     ordersSheet.getRange(oRow, 5).setValue(params.productName);
  if (params.sellerName !== undefined)      ordersSheet.getRange(oRow, 6).setValue(params.sellerName);
  if (params.productLink !== undefined)     ordersSheet.getRange(oRow, 7).setValue(params.productLink);
  if (params.platformOrderId !== undefined) ordersSheet.getRange(oRow, 8).setValue(params.platformOrderId);
  if (params.pricePaid !== undefined)       ordersSheet.getRange(oRow, 9).setValue(parseNum(params.pricePaid, 0));
  if (params.less !== undefined)            ordersSheet.getRange(oRow, 10).setValue(parseNum(params.less, 0));
  if (params.dealContactNo !== undefined)   ordersSheet.getRange(oRow, 11).setValue(params.dealContactNo);
  if (params.mediatorName !== undefined)    ordersSheet.getRange(oRow, 12).setValue(params.mediatorName);
  if (params.orderDate !== undefined)       ordersSheet.getRange(oRow, 13).setValue(params.orderDate);
  if (params.forWhom !== undefined)         ordersSheet.getRange(oRow, 14).setValue(params.forWhom);
  if (params.userId !== undefined)          ordersSheet.getRange(oRow, 15).setValue(params.userId);
  if (params.buyerLess !== undefined)       ordersSheet.getRange(oRow, 16).setValue(parseNum(params.buyerLess, 0));
  if (params.notes !== undefined)           ordersSheet.getRange(oRow, 17).setValue(params.notes);
  if (params. orderScreenshot !== undefined && params.orderScreenshot !== '') {
    ordersSheet.getRange(oRow, 20).setValue(params.orderScreenshot);
  }
  if (params.remarks !== undefined)         ordersSheet.getRange(oRow, 21).setValue(params.remarks);

  // 2. Update Tracking-specific columns in Tracking sheet (Never overwrite ArrayFormula cols!)
  if (params.actualGot !== undefined) {
    trackingSheet.getRange(tRow, 9).setValue(params.actualGot === '' ? '' : parseNum(params.actualGot, 0));
  }
  if (params.orderStatus !== undefined)     trackingSheet.getRange(tRow, 10).setValue(params.orderStatus);
  if (params.deliveryDate !== undefined)    trackingSheet.getRange(tRow, 12).setValue(params.deliveryDate);
  if (params.reviewDate !== undefined)      trackingSheet.getRange(tRow, 13).setValue(params.reviewDate);
  if (params.reviewLiveDate !== undefined)  trackingSheet.getRange(tRow, 14).setValue(params.reviewLiveDate);
  if (params.refundFormDate !== undefined)  trackingSheet.getRange(tRow, 15).setValue(params.refundFormDate);
  if (params.refundDate !== undefined)      trackingSheet.getRange(tRow, 16).setValue(params.refundDate);
  if (params.buyerActualGot !== undefined) {
    trackingSheet.getRange(tRow, 19).setValue(params.buyerActualGot === '' ? '' : parseNum(params.buyerActualGot, 0));
  }
  if (params.paymentMethod !== undefined)   trackingSheet.getRange(tRow, 20).setValue(params.paymentMethod);
  if (params.paymentStatus !== undefined)   trackingSheet.getRange(tRow, 21).setValue(params.paymentStatus);
  if (params.paymentDate !== undefined)     trackingSheet.getRange(tRow, 22).setValue(params.paymentDate);
  if (params.reviewLink !== undefined)      trackingSheet.getRange(tRow, 27).setValue(params.reviewLink);

  SpreadsheetApp.flush();

  // Check if status changed to 'Got Refund' or payment changed to 'Paid'
  const updated = findOrderRowIndices(orderObj.orderNo, orderObj.platformOrderId);
  let waReceipt = '';

  if (params.orderStatus && params.orderStatus.toLowerCase() === 'got refund' && prevStatus.toLowerCase() !== 'got refund') {
    triggerOrderNotification('GOT_REFUND', updated);
    waReceipt = buildWhatsAppReceiptText('GOT_REFUND', updated);
  }
  if (params.paymentStatus && params.paymentStatus.toLowerCase() === 'paid' && prevPaymentStatus.toLowerCase() !== 'paid') {
    triggerOrderNotification('PAID', updated);
    waReceipt = buildWhatsAppReceiptText('PAID', updated);
  }

  return {
    success: true,
    message: `Order #${orderObj.orderNo} updated successfully!`,
    order: updated,
    whatsappReceipt: waReceipt
  };
}

function handleUpdateOrderStatus(params) {
  return handleUpdateOrderFull({
    orderNo:        params.orderNo,
    platformOrderId: params.platformOrderId,
    orderStatus:    params.orderStatus,
    actualGot:      params.actualGot,
    refundDate:     params.refundDate,
    notes:          params.notes
  });
}

function handleUpdateOrderPayment(params) {
  return handleUpdateOrderFull({
    orderNo:        params.orderNo,
    platformOrderId: params.platformOrderId,
    buyerActualGot: params.buyerActualGot,
    paymentMethod:  params.paymentMethod,
    paymentStatus:  params.paymentStatus,
    paymentDate:    params.paymentDate,
    notes:          params.notes
  });
}

function handleUpdateOrderTracking(params) {
  return handleUpdateOrderFull({
    orderNo:         params.orderNo,
    platformOrderId: params.platformOrderId,
    orderStatus:     params.orderStatus,
    deliveryDate:    params.deliveryDate,
    reviewDate:      params.reviewDate,
    reviewLiveDate:  params.reviewLiveDate,
    refundFormDate:  params.refundFormDate,
    refundDate:      params.refundDate,
    reviewLink:      params.reviewLink,
    notes:           params.notes
  });
}

/**
 * Bulk Action Handler (Update 10-100 orders at once in Admin Panel)
 */
function handleBulkUpdateOrders(params) {
  const orderNos = Array.isArray(params.orderNos) ? params.orderNos : JSON.parse(params.orderNos || '[]');
  if (!orderNos.length) return { success: false, error: 'No orders selected for bulk update.' };

  const ss = getSpreadsheet();
  const trackingSheet = ss.getSheetByName(TABS.TRACKING);
  const allOrders = getMergedOrders();
  const orderMap = new Map(allOrders.map(o => [String(o.orderNo), o]));

  const bulkMode = String(params.bulkMode || 'status'); // 'status' | 'payment' | 'mediator_settle'
  const todayStr = formatDateISO(new Date());
  let updatedCount = 0;

  orderNos.forEach(no => {
    const o = orderMap.get(String(no));
    if (!o) return;
    const tRow = o.trackRowIndex;

    if (bulkMode === 'status' || bulkMode === 'mediator_settle') {
      if (params.orderStatus) {
        trackingSheet.getRange(tRow, 10).setValue(params.orderStatus);
      }
      if (params.orderStatus && params.orderStatus.toLowerCase() === 'got refund') {
        const gotAmt = params.autoFillActualGot ? o.toGet : (params.actualGot !== undefined ? parseNum(params.actualGot) : o.toGet);
        trackingSheet.getRange(tRow, 9).setValue(gotAmt);
        trackingSheet.getRange(tRow, 16).setValue(params.refundDate || todayStr);
      }
    }

    if (bulkMode === 'payment') {
      const payStatus = params.paymentStatus || 'Paid';
      const payMethod = params.paymentMethod || 'UPI';
      const payDate = params.paymentDate || todayStr;
      const buyerGot = params.autoFillBuyerGot !== false ? o.buyerToGet : parseNum(params.buyerActualGot, o.buyerToGet);

      trackingSheet.getRange(tRow, 19).setValue(buyerGot);
      trackingSheet.getRange(tRow, 20).setValue(payMethod);
      trackingSheet.getRange(tRow, 21).setValue(payStatus);
      trackingSheet.getRange(tRow, 22).setValue(payDate);
    }

    updatedCount++;
  });

  SpreadsheetApp.flush();
  return {
    success: true,
    updatedCount: updatedCount,
    message: `Successfully updated ${updatedCount} orders in bulk!`
  };
}

/**
 * Parent Buyer Batch Payout Settlement:
 * Settles all selected unpaid "Got Refund" orders for a Parent Buyer and returns
 * a single consolidated WhatsApp receipt with all settled Order IDs and total payout.
 */
function handleBatchSettleParentBuyer(params) {
  const orderNos = Array.isArray(params.orderNos) ? params.orderNos : JSON.parse(params.orderNos || '[]');
  const paymentMethod = String(params.paymentMethod || 'UPI').trim();
  const paymentDate = String(params.paymentDate || formatDateISO(new Date())).trim();

  if (!orderNos.length) return { success: false, error: 'No orders selected for payout.' };

  const ss = getSpreadsheet();
  const trackingSheet = ss.getSheetByName(TABS.TRACKING);
  const allOrders = getMergedOrders();
  const orderMap = new Map(allOrders.map(o => [String(o.orderNo), o]));

  let totalPayout = 0;
  const settledItems = [];

  orderNos.forEach(no => {
    const o = orderMap.get(String(no));
    if (!o) return;
    const tRow = o.trackRowIndex;
    const payAmt = o.buyerToGet;

    trackingSheet.getRange(tRow, 19).setValue(payAmt);
    trackingSheet.getRange(tRow, 20).setValue(paymentMethod);
    trackingSheet.getRange(tRow, 21).setValue('Paid');
    trackingSheet.getRange(tRow, 22).setValue(paymentDate);

    totalPayout += payAmt;
    settledItems.push(o);
  });

  SpreadsheetApp.flush();

  const lines = settledItems.map((item, idx) =>
    `${idx + 1}. #${item.orderNo} | ${item.platformOrderId} | ${item.productName.slice(0, 28)}... → *₹${item.buyerToGet}*`
  ).join('\n');

  const receipt = [
    `✅ *SASTADEAL — CONSOLIDATED PAYOUT RECEIPT*`,
    `👤 *Buyer:* ${params.parentName || settledItems[0]?.userId || 'Buyer'}`,
    `📅 *Payment Date:* ${paymentDate}`,
    `💳 *Method:* ${paymentMethod}`,
    `📦 *Orders Settled:* ${settledItems.length}`,
    `────────────────────`,
    lines,
    `────────────────────`,
    `💰 *TOTAL PAID: ₹${round2(totalPayout)}*`
  ].join('\n');

  return {
    success: true,
    settledCount: settledItems.length,
    totalPayout: round2(totalPayout),
    whatsappReceipt: receipt,
    message: `Settled ${settledItems.length} orders totaling ₹${round2(totalPayout)}!`
  };
}

function handleMediatorNote(auth, params) {
  const orderObj = findOrderRowIndices(params.orderNo, params.platformOrderId);
  if (!orderObj) return { success: false, error: 'Order not found.' };

  if (auth.user.role === 'mediator' &&
      orderObj.mediatorName.toLowerCase() !== String(auth.user.name || '').toLowerCase()) {
    return { success: false, error: 'You can only add notes to your own mediator orders.' };
  }

  const ss = getSpreadsheet();
  const ordersSheet = ss.getSheetByName(TABS.ORDERS);
  // Write to Orders Col Q (17) so Tracking!Z2 ArrayFormula stays intact
  ordersSheet.getRange(orderObj.orderRowIndex, 17).setValue(String(params.notes || '').trim());
  SpreadsheetApp.flush();

  return { success: true, message: `Note saved for Order #${orderObj.orderNo}.` };
}

function handleDeleteOrder(orderNo) {
  const orderObj = findOrderRowIndices(orderNo, null);
  if (!orderObj) return { success: false, error: 'Order not found.' };

  const ss = getSpreadsheet();
  const ordersSheet = ss.getSheetByName(TABS.ORDERS);
  const trackingSheet = ss.getSheetByName(TABS.TRACKING);

  if (orderObj.orderRowIndex > 1) ordersSheet.deleteRow(orderObj.orderRowIndex);
  if (orderObj.trackRowIndex > 1) trackingSheet.deleteRow(orderObj.trackRowIndex);
  SpreadsheetApp.flush();

  return { success: true, message: `Order #${orderNo} deleted.` };
}

function findOrderRowIndices(orderNo, platformOrderId) {
  const all = getMergedOrders();
  return all.find(o =>
    (orderNo !== undefined && orderNo !== null && String(o.orderNo) === String(orderNo)) ||
    (platformOrderId && String(o.platformOrderId).toLowerCase() === String(platformOrderId).toLowerCase())
  );
}

// ─── 10. ACCOUNTS, MEDIATORS, DEALS & HIGHLIGHTS MANAGEMENT ──────────────

function handleSaveAccount(params) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.ACCOUNTS);
  const rows = sheet.getDataRange().getValues();

  const userId = String(params.userId || '').trim();
  if (!userId) return { success: false, error: 'UserID is required.' };

  const rowValues = [
    userId,
    String(params.name || '').trim(),
    String(params.accountType || 'Main').trim(),
    String(params.mobile || '').trim(),
    String(params.whatsApp || ('91' + String(params.mobile || '').replace(/\D/g, '').slice(-10))).trim(),
    String(params.parentUserId || userId).trim(),
    String(params.email || '').trim(),
    String(params.role || 'buyer').trim().toLowerCase(),
    String(params.password || '123456789').trim(),
    String(params.profileLink || '').trim()
  ];

  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0] || '').trim().toLowerCase() === userId.toLowerCase()) {
      sheet.getRange(i + 1, 1, 1, 10).setValues([rowValues]);
      return { success: true, message: `Account ${userId} updated.` };
    }
  }

  sheet.appendRow(rowValues);
  return { success: true, message: `Account ${userId} added.` };
}

function handleDeleteAccount(userId) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.ACCOUNTS);
  const rows = sheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0] || '').trim().toLowerCase() === String(userId || '').trim().toLowerCase()) {
      sheet.deleteRow(i + 1);
      return { success: true, message: `Account ${userId} removed.` };
    }
  }
  return { success: false, error: 'Account not found.' };
}

function handleSaveMediator(params) {
  const ss = getSpreadsheet();
  const medSheet = ss.getSheetByName(TABS.MEDIATOR);
  const rows = medSheet.getDataRange().getValues();

  const name = String(params.name || '').trim();
  const contact = String(params.contact || '').replace(/\D/g, '').slice(-10);
  const whatsApp = String(params.whatsApp || (contact ? '91' + contact : '91')).trim();
  const password = String(params.password || '123456').trim();

  if (!name) return { success: false, error: 'Mediator Name is required.' };

  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0] || '').trim().toLowerCase() === name.toLowerCase()) {
      medSheet.getRange(i + 1, 1, 1, 4).setValues([[name, contact, whatsApp, password]]);
      return { success: true, message: `Mediator "${name}" updated.` };
    }
  }

  medSheet.appendRow([name, contact, whatsApp, password]);
  return { success: true, message: `Mediator "${name}" added.` };
}

function handleDeleteMediator(name) {
  const ss = getSpreadsheet();
  const medSheet = ss.getSheetByName(TABS.MEDIATOR);
  const rows = medSheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0] || '').trim().toLowerCase() === String(name || '').trim().toLowerCase()) {
      medSheet.deleteRow(i + 1);
      return { success: true, message: `Mediator "${name}" deleted.` };
    }
  }
  return { success: false, error: 'Mediator not found.' };
}

function handleSaveDeal(params) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.DEALS);
  const rows = sheet.getDataRange().getValues();

  const dealId = String(params.dealId || ('D' + Date.now())).trim();
  const rowData = [
    dealId,
    String(params.title || '').trim(),
    String(params.platform || 'Amazon').trim(),
    String(params.productUrl || '').trim(),
    parseNum(params.price, 0),
    parseNum(params.lessAmount, 0),
    String(params.instructions || '').trim(),
    String(params.imageUrl || '').trim(),
    String(params.status || 'active').trim().toLowerCase(),
    formatDateISO(new Date())
  ];

  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0] || '').trim() === dealId) {
      sheet.getRange(i + 1, 1, 1, 10).setValues([rowData]);
      return { success: true, message: 'Deal updated!', dealId: dealId };
    }
  }

  sheet.appendRow(rowData);
  return { success: true, message: 'New deal published!', dealId: dealId };
}

function handleDeleteDeal(dealId) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.DEALS);
  const rows = sheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0] || '').trim() === String(dealId || '').trim()) {
      sheet.deleteRow(i + 1);
      return { success: true, message: 'Deal deleted.' };
    }
  }
  return { success: false, error: 'Deal not found.' };
}

function handleRequestDeal(auth, params) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.DEAL_REQUESTS);
  const reqId = 'REQ' + Date.now();
  const buyerName = String(params.buyerName || auth.user.name || '').trim();
  const buyerMobile = String(params.buyerMobile || auth.user.mobile || '').trim();
  const dealTitle = String(params.dealTitle || '').trim();
  const dealId = String(params.dealId || '').trim();

  sheet.appendRow([
    reqId,
    buyerName,
    buyerMobile,
    dealTitle,
    dealId,
    new Date(),
    'pending'
  ]);

  // Trigger #4: Deal Requested → Notify Admin
  const msg = `🔥 *New Deal Request — SastaDeal*\n👤 Buyer: ${buyerName}\n📱 Mobile: ${buyerMobile}\n🛍️ Deal: ${dealTitle}\n🆔 Deal ID: ${dealId}`;
  sendCallMeBotWhatsApp(msg);

  return {
    success: true,
    requestId: reqId,
    message: 'Deal requested! Admin has been notified on WhatsApp.'
  };
}

function handleUpdateDealRequest(params) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.DEAL_REQUESTS);
  const rows = sheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0] || '').trim() === String(params.requestId || '').trim()) {
      sheet.getRange(i + 1, 7).setValue(String(params.status || 'handled').trim());
      return { success: true, message: 'Deal request updated.' };
    }
  }
  return { success: false, error: 'Deal request not found.' };
}

/**
 * Highlights stored in Instructions tab using exact format:
 * HIGHLIGHT: title | message | role | date
 */
function getHighlightsList(forRole) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.INSTRUCTIONS);
  if (!sheet) return [];

  const rows = sheet.getDataRange().getValues();
  const list = [];
  for (let i = 0; i < rows.length; i++) {
    const cell = String(rows[i][0] || '').trim();
    if (cell.startsWith('HIGHLIGHT:')) {
      const raw = cell.replace(/^HIGHLIGHT:\s*/i, '');
      const parts = raw.split('|').map(s => s.trim());
      const item = {
        rowIndex: i + 1,
        title:    parts[0] || 'Announcement',
        message:  parts[1] || '',
        role:     (parts[2] || 'all').toLowerCase(),
        date:     parts[3] || ''
      };
      if (forRole === 'admin' || item.role === 'all' || item.role === forRole) {
        list.push(item);
      }
    }
  }
  return list.reverse();
}

function handleSaveHighlight(params) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.INSTRUCTIONS);
  const title = String(params.title || 'Important').replace(/\|/g, '-').trim();
  const message = String(params.message || '').replace(/\|/g, '-').trim();
  const role = String(params.targetRole || 'all').trim().toLowerCase();
  const dateStr = formatDateISO(new Date());

  const line = `HIGHLIGHT: ${title} | ${message} | ${role} | ${dateStr}`;
  sheet.appendRow([line]);
  return { success: true, message: 'Highlight published!' };
}

function handleDeleteHighlight(rowIndex) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.INSTRUCTIONS);
  const r = Number(rowIndex);
  if (r > 0 && r <= sheet.getLastRow()) {
    sheet.deleteRow(r);
    return { success: true, message: 'Highlight deleted.' };
  }
  return { success: false, error: 'Invalid highlight row.' };
}

// ─── 11. GOOGLE DRIVE SCREENSHOT UPLOAD (<=200KB COMPRESSED) ─────────────

function handleUploadScreenshot(auth, params) {
  const base64Data = String(params.base64Data || '');
  const fileName = String(params.fileName || ('Order_' + Date.now() + '.jpg'));
  const mimeType = String(params.mimeType || 'image/jpeg');

  if (!base64Data) return { success: false, error: 'No image data provided.' };

  const cleanBase64 = base64Data.includes(',') ? base64Data.split(',')[1] : base64Data;
  const decoded = Utilities.base64Decode(cleanBase64);
  const blob = Utilities.newBlob(decoded, mimeType, fileName);

  let folder;
  if (DRIVE_FOLDER_ID && DRIVE_FOLDER_ID !== 'YOUR_GOOGLE_DRIVE_FOLDER_ID_HERE') {
    folder = DriveApp.getFolderById(DRIVE_FOLDER_ID);
  } else {
    folder = DriveApp.getRootFolder();
  }

  const file = folder.createFile(blob);
  file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
  const fileUrl = `https://drive.google.com/uc?export=view&id=${file.getId()}`;

  return {
    success: true,
    fileId: file.getId(),
    url: fileUrl,
    viewUrl: file.getUrl()
  };
}

// ─── 12. WHATSAPP (CALLMEBOT) & EMAIL (GMAILAPP) NOTIFICATIONS ───────────

function buildWhatsAppReceiptText(type, o) {
  if (type === 'ORDER_SUBMITTED') {
    return [
      `🛒 *SASTADEAL — ORDER SUBMITTED (#${o.orderNo})*`,
      `📅 Date: ${o.orderDate}`,
      `🌐 Platform: ${o.orderedPlatform}`,
      `👤 Account: ${o.accountName} (${o.userId})`,
      `📦 Product: ${o.productName}`,
      `🆔 Order ID: *${o.platformOrderId}*`,
      `💵 Price Paid: ₹${o.pricePaid}`,
      `🔻 Buyer Less: -₹${o.buyerLess}`,
      `💰 *You Will Get: ₹${o.buyerToGet}*`,
      o.notes ? `📝 Notes: ${o.notes}` : '',
      o.orderScreenshot ? `🖼️ Screenshot: ${o.orderScreenshot}` : ''
    ].filter(Boolean).join('\n');
  }

  if (type === 'GOT_REFUND') {
    return [
      `🎉 *SASTADEAL — REFUND RECEIVED (#${o.orderNo})*`,
      `📅 Order Date: ${o.orderDate}`,
      `🌐 Platform: ${o.orderedPlatform}`,
      `👤 Account: ${o.accountName}`,
      `📦 Product: ${o.productName}`,
      `🆔 Order ID: *${o.platformOrderId}*`,
      `💵 Price Paid: ₹${o.pricePaid}`,
      `🔻 Buyer Less: -₹${o.buyerLess}`,
      `✅ *Refund Approved (To Get): ₹${o.buyerToGet}*`,
      `⏳ Payout will be credited to your account shortly.`
    ].join('\n');
  }

  if (type === 'PAID') {
    return [
      `💸 *SASTADEAL — PAYMENT SETTLED (#${o.orderNo})*`,
      `📅 Payment Date: ${o.paymentDate || formatDateISO(new Date())}`,
      `🌐 Platform: ${o.orderedPlatform}`,
      `👤 Account: ${o.accountName}`,
      `📦 Product: ${o.productName}`,
      `🆔 Order ID: *${o.platformOrderId}*`,
      `💵 Price Paid: ₹${o.pricePaid}`,
      `🔻 Buyer Less: -₹${o.buyerLess}`,
      `💰 *Amount Paid: ₹${o.buyerActualGot !== null ? o.buyerActualGot : o.buyerToGet}*`,
      `🏦 Method: ${o.paymentMethod || 'UPI'}`,
      o.notes ? `📝 Notes: ${o.notes}` : ''
    ].filter(Boolean).join('\n');
  }

  return '';
}

function triggerOrderNotification(type, orderObj) {
  const text = buildWhatsAppReceiptText(type, orderObj);
  if (!text) return;

  // Send WhatsApp to Admin via CallMeBot
  sendCallMeBotWhatsApp(text);

  // Send Email to Buyer if email exists in Accounts tab
  const buyerContact = findBuyerContactByUserId(orderObj.userId);
  if (buyerContact && buyerContact.email && buyerContact.email.includes('@')) {
    const subjectMap = {
      'ORDER_SUBMITTED': `SastaDeal: Order #${orderObj.orderNo} Submitted (${orderObj.platformOrderId})`,
      'GOT_REFUND':      `SastaDeal: Refund Approved for Order #${orderObj.orderNo}`,
      'PAID':            `SastaDeal: Payout Sent for Order #${orderObj.orderNo}`
    };
    sendEmailSafe(buyerContact.email, subjectMap[type] || 'SastaDeal Order Update', text.replace(/\*/g, ''));
  }
}

function findBuyerContactByUserId(userId) {
  if (!userId) return null;
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(TABS.ACCOUNTS);
  if (!sheet) return null;
  const rows = sheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0] || '').trim().toLowerCase() === String(userId).trim().toLowerCase()) {
      return {
        name: String(rows[i][1] || '').trim(),
        mobile: String(rows[i][3] || '').replace(/\D/g, '').slice(-10),
        whatsApp: String(rows[i][4] || '').replace(/\D/g, ''),
        email: String(rows[i][6] || '').trim()
      };
    }
  }
  return null;
}

function sendCallMeBotWhatsApp(messageText, customPhone) {
  if (!CALLMEBOT_API_KEY || CALLMEBOT_API_KEY === 'YOUR_CALLMEBOT_API_KEY_HERE') {
    return { sent: false, reason: 'CallMeBot API key not configured' };
  }
  try {
    const phone = String(customPhone || ADMIN_WHATSAPP).replace(/\D/g, '');
    const url = `https://api.callmebot.com/whatsapp.php?phone=${phone}&text=${encodeURIComponent(messageText)}&apikey=${encodeURIComponent(CALLMEBOT_API_KEY)}`;
    UrlFetchApp.fetch(url, { muteHttpExceptions: true });
    return { sent: true };
  } catch (e) {
    return { sent: false, error: e.message };
  }
}

function sendEmailSafe(toEmail, subject, bodyText) {
  try {
    if (!toEmail || !toEmail.includes('@')) return { sent: false };
    GmailApp.sendEmail(toEmail, subject, bodyText);
    return { sent: true };
  } catch (e) {
    return { sent: false, error: e.message };
  }
}

function handleSubmitQuery(auth, params) {
  const subject = `[SastaDeal Query] From ${auth.user.name} (${auth.user.role.toUpperCase()}) - Order ${params.orderId || 'General'}`;
  const body = [
    `Role: ${auth.user.role}`,
    `User: ${auth.user.name} (${auth.user.userId})`,
    `Mobile: ${auth.user.mobile || 'N/A'}`,
    `Order Reference: ${params.orderId || 'N/A'}`,
    `Query Subject: ${params.subject || 'Support Query'}`,
    `Message:\n${params.message || ''}`
  ].join('\n');

  const adminEmail = Session.getEffectiveUser().getEmail();
  if (adminEmail) {
    sendEmailSafe(adminEmail, subject, body);
  }
  sendCallMeBotWhatsApp(`📩 *New Support Query*\nFrom: ${auth.user.name} (${auth.user.role})\nOrder: ${params.orderId || 'General'}\nMsg: ${params.message || ''}`);

  return {
    success: true,
    message: 'Your query has been sent to Admin via Email & WhatsApp!'
  };
}

function handleManualNotification(params) {
  const channel = String(params.channel || 'whatsapp').toLowerCase();
  const recipient = String(params.recipient || '').trim();
  const subject = String(params.subject || 'SastaDeal Notification').trim();
  const message = String(params.message || '').trim();

  if (!message) return { success: false, error: 'Message content cannot be empty.' };

  if (channel === 'email') {
    const res = sendEmailSafe(recipient, subject, message);
    return { success: res.sent, message: res.sent ? `Email sent to ${recipient}` : ('Email failed: ' + res.error) };
  } else {
    const res = sendCallMeBotWhatsApp(message, recipient || ADMIN_WHATSAPP);
    return {
      success: true,
      callMeBotSent: res.sent,
      waWebUrl: `https://wa.me/${recipient.replace(/\D/g, '')}?text=${encodeURIComponent(message)}`,
      message: res.sent ? 'WhatsApp notification sent via CallMeBot!' : 'Prepared WhatsApp link.'
    };
  }
}
