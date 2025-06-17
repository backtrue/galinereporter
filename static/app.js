// static/app.js

// 使用 DOMContentLoaded 確保 HTML 完全載入後再執行腳本
document.addEventListener('DOMContentLoaded', function() {
    
    // --- 自動隱藏 Flash 訊息 ---
    const flashMessages = document.querySelectorAll('.flash-messages .flash-success, .flash-messages .flash-info, .flash-messages .flash-warning, .flash-messages .flash-error');
    if (flashMessages.length > 0) {
        flashMessages.forEach(function(flashMessage) {
            setTimeout(() => {
                flashMessage.style.transition = 'opacity 0.5s ease-out';
                flashMessage.style.opacity = '0';
                setTimeout(() => {
                    if (flashMessage.parentNode) {
                       flashMessage.parentNode.removeChild(flashMessage);
                    }
                }, 500); 
            }, 5000); // 顯示 5 秒
        });
    }

    // --- 時區設定表單 AJAX 處理 ---
    const timezoneForm = document.getElementById('timezone-form');
    const timezoneSelect = document.getElementById('timezone-select');
    const updateTimezoneBtn = document.getElementById('update-timezone-btn');
    const timezoneFeedback = document.getElementById('timezone-feedback');
    const currentTimezoneDisplay = document.getElementById('current-timezone-display');

    if (timezoneForm && updateTimezoneBtn && timezoneSelect && timezoneFeedback && currentTimezoneDisplay) {
        
        timezoneForm.addEventListener('submit', function(event) {
            event.preventDefault(); // 阻止表單的預設提交

            const selectedTimezone = timezoneSelect.value;
            const originalButtonText = updateTimezoneBtn.textContent;
            
            updateTimezoneBtn.disabled = true;
            updateTimezoneBtn.textContent = '更新中...';
            timezoneFeedback.textContent = '';
            timezoneFeedback.className = ''; 

            const formData = new FormData();
            formData.append('timezone', selectedTimezone);

            // ----- 修改：直接使用相對路徑 -----
            fetch("/set-timezone", { 
                 method: 'POST',
                 body: formData 
            })
            // --------------------------------
            .then(response => { 
                if (!response.ok) {
                    return response.json().catch(() => { 
                        throw new Error(`伺服器錯誤: ${response.status} ${response.statusText}`);
                    }).then(errData => {
                         throw new Error(errData.message || `伺服器錯誤: ${response.status}`);
                    });
                }
                return response.json(); 
            })
            .then(data => { 
                if (data.status === 'success') {
                    timezoneFeedback.textContent = data.message || '更新成功！';
                    timezoneFeedback.className = 'feedback-success';
                    currentTimezoneDisplay.textContent = data.new_timezone || selectedTimezone;
                    timezoneSelect.value = data.new_timezone || selectedTimezone;
                } else {
                    throw new Error(data.message || '後端返回未知錯誤。');
                }
            })
            .catch(error => { 
                console.error('更新時區時發生錯誤:', error);
                timezoneFeedback.textContent = '錯誤：' + error.message;
                timezoneFeedback.className = 'feedback-error';
            })
            .finally(() => { 
                updateTimezoneBtn.disabled = false;
                updateTimezoneBtn.textContent = originalButtonText;
                setTimeout(() => {
                    timezoneFeedback.textContent = '';
                    timezoneFeedback.className = '';
                }, 5000); 
            });
        });
    } else {
        // 檢查是否有元素找不到，方便除錯
        if (!timezoneForm) console.warn("JS Warning: 找不到 ID 為 'timezone-form' 的表單。");
        if (!updateTimezoneBtn) console.warn("JS Warning: 找不到 ID 為 'update-timezone-btn' 的按鈕。");
        if (!timezoneSelect) console.warn("JS Warning: 找不到 ID 為 'timezone-select' 的下拉選單。");
        if (!timezoneFeedback) console.warn("JS Warning: 找不到 ID 為 'timezone-feedback' 的 span。");
        if (!currentTimezoneDisplay) console.warn("JS Warning: 找不到 ID 為 'current-timezone-display' 的 span。");
    }

    // --- 啟用/停用排程的 AJAX 處理 (之後可以加在這裡) ---
    // const scheduleForm = document.getElementById('schedule-toggle-form');
    // ... (類似的邏輯)

}); // DOMContentLoaded 結束