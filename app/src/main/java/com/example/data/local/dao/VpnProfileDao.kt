package com.example.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.example.data.local.entity.VpnProfileEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface VpnProfileDao {
    @Query("SELECT * FROM vpn_profiles ORDER BY isFavorite DESC, id DESC")
    fun getAllProfiles(): Flow<List<VpnProfileEntity>>

    @Query("SELECT * FROM vpn_profiles WHERE id = :id LIMIT 1")
    suspend fun getProfileById(id: Long): VpnProfileEntity?

    @Query("SELECT * FROM vpn_profiles WHERE protocol = :protocol ORDER BY isFavorite DESC, id DESC")
    fun getProfilesByProtocol(protocol: String): Flow<List<VpnProfileEntity>>

    @Query("SELECT * FROM vpn_profiles WHERE isFavorite = 1 ORDER BY id DESC")
    fun getFavoriteProfiles(): Flow<List<VpnProfileEntity>>

    @Query("SELECT * FROM vpn_profiles WHERE name LIKE '%' || :query || '%' OR server LIKE '%' || :query || '%' OR sni LIKE '%' || :query || '%'")
    fun searchProfiles(query: String): Flow<List<VpnProfileEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertProfile(profile: VpnProfileEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertProfiles(profiles: List<VpnProfileEntity>): List<Long>

    @Update
    suspend fun updateProfile(profile: VpnProfileEntity)

    @Delete
    suspend fun deleteProfile(profile: VpnProfileEntity)

    @Query("DELETE FROM vpn_profiles WHERE id = :id")
    suspend fun deleteProfileById(id: Long)

    @Query("DELETE FROM vpn_profiles WHERE isPreset = 0")
    suspend fun deleteAllCustomProfiles()

    @Query("UPDATE vpn_profiles SET lastPingMs = :pingMs WHERE id = :id")
    suspend fun updatePing(id: Long, pingMs: Int)

    @Query("UPDATE vpn_profiles SET isFavorite = :isFavorite WHERE id = :id")
    suspend fun updateFavorite(id: Long, isFavorite: Boolean)

    @Query("SELECT COUNT(*) FROM vpn_profiles")
    suspend fun getProfileCount(): Int
}
