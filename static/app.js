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

// 基本功能初始化
document.addEventListener('DOMContentLoaded', function() {
    console.log('頁面已載入完成');

    // 檢查是否有 timezone 相關元素，如果有才初始化
    const timezoneForm = document.getElementById('timezone-form');
    if (timezoneForm) {
        initializeTimezoneForm();
    }
});

// 時區功能初始化（僅在相關元素存在時）
function initializeTimezoneForm() {
    const timezoneForm = document.getElementById('timezone-form');
    const updateTimezoneBtn = document.getElementById('update-timezone-btn');
    const timezoneSelect = document.getElementById('timezone-select');
    const timezoneFeedback = document.getElementById('timezone-feedback');
    const currentTimezoneDisplay = document.getElementById('current-timezone-display');

    // 確保所有必要元素都存在
    if (!timezoneForm || !updateTimezoneBtn || !timezoneSelect || !timezoneFeedback || !currentTimezoneDisplay) {
        console.log('時區表單元素不完整，跳過初始化');
        return;
    }

    // 時區更新功能
    timezoneForm.addEventListener('submit', function(e) {
        e.preventDefault();

        const selectedTimezone = timezoneSelect.value;
        if (!selectedTimezone) {
            timezoneFeedback.textContent = '請選擇時區';
            timezoneFeedback.className = 'alert alert-danger';
            timezoneFeedback.style.display = 'block';
            return;
        }

        updateTimezoneBtn.disabled = true;
        updateTimezoneBtn.textContent = '更新中...';

        fetch('/update_timezone', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                timezone: selectedTimezone
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                timezoneFeedback.textContent = '時區更新成功！';
                timezoneFeedback.className = 'alert alert-success';
                currentTimezoneDisplay.textContent = selectedTimezone;
            } else {
                timezoneFeedback.textContent = data.error || '更新失敗，請稍後再試';
                timezoneFeedback.className = 'alert alert-danger';
            }
            timezoneFeedback.style.display = 'block';
        })
        .catch(error => {
            console.error('Error:', error);
            timezoneFeedback.textContent = '網路錯誤，請稍後再試';
            timezoneFeedback.className = 'alert alert-danger';
            timezoneFeedback.style.display = 'block';
        })
        .finally(() => {
            updateTimezoneBtn.disabled = false;
            updateTimezoneBtn.textContent = '更新時區';
        });
    });
}

    // --- 啟用/停用排程的 AJAX 處理 (之後可以加在這裡) ---
    // const scheduleForm = document.getElementById('schedule-toggle-form');
    // ... (類似的邏輯)

}); // DOMContentLoaded 結束